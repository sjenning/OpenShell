// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{auth::test_scope, backend::CredentialDriver, repository::Mutation};
use openshell_core::proto::{
    CredentialHandle,
    credentials::v1::{
        DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential,
        StoreCredentialRequest,
    },
};
use openshell_driver_db_credstore::DbCredstoreCredentialDriver;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tonic::Code;
use wire::credential_store_server::CredentialStore as _;

pub(super) mod mtls;
mod postgres;
mod reservations;
mod watch;

const A: &str = "spiffe://test.example/gateway/a";
const B: &str = "spiffe://test.example/gateway/b";

#[derive(Debug)]
struct Driver {
    inner: DbCredstoreCredentialDriver,
    resolves: AtomicUsize,
    block: AtomicBool,
    fail: AtomicBool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[tonic::async_trait]
impl CredentialDriver for Driver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        self.inner.store_credential(request).await
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }
    async fn resolve_credentials(
        &self,
        request: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("secret-backend-diagnostic"));
        }
        if self.block.swap(false, Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        self.inner.resolve_credentials(request).await
    }
}
struct Fixture {
    service: CredentialStoreService,
    driver: Arc<Driver>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let mut config = toml::Table::new();
        config.insert(
            "key_encryption_key_path".to_string(),
            toml::Value::String(dir.path().join("key.bin").display().to_string()),
        );
        let driver = Arc::new(Driver {
            inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
            resolves: AtomicUsize::new(0),
            block: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let erased: Arc<dyn CredentialDriver> = driver.clone();
        let drivers = BTreeMap::from([("db".to_string(), erased)]);
        let storage = CredentialStorage::new(drivers, "db".to_string()).unwrap();
        let policy = GatewayPolicy::new(BTreeMap::from([
            (A.to_string(), vec!["default".to_string()]),
            (B.to_string(), vec!["default".to_string()]),
        ]))
        .unwrap();
        let service =
            CredentialStoreService::new(repository, storage, policy, Duration::from_secs(2))
                .unwrap();
        Self {
            service,
            driver,
            _dir: dir,
        }
    }
    fn runtime(&self) -> Arc<Runtime> {
        self.service.runtime.clone()
    }
}
fn wire_owner() -> wire::SecretOwner {
    wire::SecretOwner {
        workspace: "default".to_string(),
        provider_id: "provider-id".to_string(),
        credential_key: "TOKEN".to_string(),
        provider: "display-name".to_string(),
    }
}
fn put() -> wire::PutSecretRequest {
    wire::PutSecretRequest {
        owner: Some(wire_owner()),
        reference: String::new(),
        value: "private-value".to_string(),
        expiration_time: None,
        expected_version: None,
        idempotency_key: "put-one".to_string(),
    }
}
async fn create(runtime: &Arc<Runtime>) -> wire::PutSecretResponse {
    runtime
        .clone()
        .put(test_scope(A), put(), idempotency("put-one").unwrap())
        .await
        .unwrap()
}
fn resolve(reference: &str, purpose: wire::ResolvePurpose) -> wire::ResolveSecretsRequest {
    wire::ResolveSecretsRequest {
        secrets: vec![wire::ResolveSecretRequest {
            request_id: "one".to_string(),
            owner: Some(wire_owner()),
            reference: reference.to_string(),
            expected_version: None,
        }],
        purpose: purpose as i32,
    }
}

#[tokio::test]
async fn static_lifecycle_preserves_references_versions_and_durable_idempotency() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let first = create(&runtime).await;
    let mut retry = put();
    retry.owner.as_mut().unwrap().provider = "renamed-audit-name".to_string();
    let repeated = runtime
        .clone()
        .put(test_scope(A), retry, idempotency("put-one").unwrap())
        .await
        .unwrap();
    assert_eq!(repeated, first);
    let wrong = wire::PutSecretRequest {
        value: "different".to_string(),
        ..put()
    };
    assert_eq!(
        runtime
            .clone()
            .put(test_scope(A), wrong, idempotency("put-one").unwrap())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let response = runtime
        .resolve(
            &test_scope(A),
            resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery),
        )
        .await
        .unwrap();
    assert_eq!(response.secrets[0].value, "private-value");
    assert_eq!(response.secrets[0].version, 1);
    assert!(
        runtime
            .resolve(
                &test_scope(B),
                resolve(&first.reference, wire::ResolvePurpose::OperatorExport)
            )
            .await
            .is_err()
    );
    let update = wire::PutSecretRequest {
        reference: first.reference.clone(),
        value: "rotated".to_string(),
        expected_version: Some(1),
        idempotency_key: "put-two".to_string(),
        ..put()
    };
    let second = runtime
        .clone()
        .put(test_scope(A), update, idempotency("put-two").unwrap())
        .await
        .unwrap();
    assert_eq!(second.reference, first.reference);
    assert_eq!(second.version, 2);
    let deleted = wire::DeleteSecretRequest {
        owner: Some(wire_owner()),
        reference: first.reference.clone(),
        expected_version: Some(2),
        idempotency_key: "delete".to_string(),
    };
    assert_eq!(
        runtime
            .clone()
            .delete(
                test_scope(A),
                deleted.clone(),
                idempotency("delete").unwrap()
            )
            .await
            .unwrap()
            .version,
        3
    );
    assert_eq!(
        runtime
            .clone()
            .delete(test_scope(A), deleted, idempotency("delete").unwrap())
            .await
            .unwrap()
            .version,
        3
    );
    assert_eq!(
        runtime
            .resolve(
                &test_scope(A),
                resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery)
            )
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    runtime.maintenance().await.unwrap();
    let state = runtime
        .repository
        .references(&test_scope(A))
        .load(&first.reference)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert!(state.revoked);
    assert!(state.pending_deletions.is_empty());
    let store = runtime.repository.for_gateway(&test_scope(A));
    assert_eq!(store.events_after(0, 10).await.unwrap().len(), 3);
    assert!(
        store
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn metadata_reads_do_not_touch_backends_and_batch_authorization_precedes_all_values() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let first = create(&runtime).await;
    let before = fixture.driver.resolves.load(Ordering::SeqCst);
    fixture.driver.fail.store(true, Ordering::SeqCst);
    let metadata = runtime
        .resolve(
            &test_scope(A),
            resolve(&first.reference, wire::ResolvePurpose::MetadataInspection),
        )
        .await
        .unwrap();
    assert!(metadata.secrets[0].value.is_empty());
    assert_eq!(
        openshell_core::time::duration_to_std(metadata.secrets[0].cache_ttl.as_ref().unwrap())
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), before);
    let mut batch = resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery);
    let mut bad = batch.secrets[0].clone();
    bad.request_id = "bad".to_string();
    bad.owner.as_mut().unwrap().workspace = "unauthorized".to_string();
    batch.secrets.push(bad);
    assert_eq!(
        runtime
            .resolve(&test_scope(A), batch)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), before);
    let error = runtime
        .resolve(
            &test_scope(A),
            resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(!error.message().contains("secret"));
}

#[tokio::test]
async fn rotation_during_value_resolution_aborts_the_entire_snapshot() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let first = create(&runtime).await;
    fixture.driver.block.store(true, Ordering::SeqCst);
    let reader = runtime.clone();
    let reference = first.reference.clone();
    let task = tokio::spawn(async move {
        reader
            .resolve(
                &test_scope(A),
                resolve(&reference, wire::ResolvePurpose::SandboxDelivery),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), fixture.driver.started.notified())
        .await
        .unwrap();
    let update = wire::PutSecretRequest {
        reference: first.reference,
        expected_version: Some(1),
        idempotency_key: "race".to_string(),
        value: "new".to_string(),
        ..put()
    };
    runtime
        .clone()
        .put(test_scope(A), update, idempotency("race").unwrap())
        .await
        .unwrap();
    fixture.driver.release.notify_one();
    assert_eq!(task.await.unwrap().unwrap_err().code(), Code::Aborted);
}

#[tokio::test]
async fn claiming_an_abandoned_candidate_fences_late_publication_before_backend_deletion() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let scope = test_scope(A);
    let owner = owner(Some(&wire_owner())).unwrap();
    let store = runtime.repository.for_gateway(&scope);
    let backing = runtime
        .storage
        .stage(&scope, &owner, VALUE_PURPOSE, "unpublished".to_string())
        .await
        .unwrap();
    let candidate = Candidate {
        operation_key: "secret-operation:abandoned".to_string(),
        owner: owner.clone(),
        purpose: VALUE_PURPOSE.to_string(),
        backing: backing.clone(),
    };
    let payload = encode(&candidate).unwrap();
    store
        .commit(
            &[Mutation::Put {
                kind: CANDIDATE_KIND.to_string(),
                key: "candidate".to_string(),
                expected: None,
                payload: payload.clone(),
            }],
            &[],
        )
        .await
        .unwrap();
    store
        .commit(
            &[Mutation::Put {
                kind: CANDIDATE_KIND.to_string(),
                key: "candidate".to_string(),
                expected: Some(1),
                payload,
            }],
            &[],
        )
        .await
        .unwrap();
    let state = ReferenceState {
        owner: owner.clone(),
        version: 1,
        backing: backing.clone(),
        expiration_time_ms: None,
        revoked: false,
        pending_value: false,
        pending_deletions: Vec::new(),
    };
    let refs = runtime.repository.references(&scope);
    let (write, event) = refs
        .prepare("must-not-publish", None, &state)
        .await
        .unwrap();
    let late = store
        .commit(
            &[
                write,
                Mutation::Delete {
                    kind: CANDIDATE_KIND.to_string(),
                    key: "candidate".to_string(),
                    expected: 1,
                },
            ],
            &event.into_iter().collect::<Vec<_>>(),
        )
        .await
        .unwrap_err();
    assert_eq!(late.code(), Code::Aborted);
    assert!(refs.load("must-not-publish").await.unwrap().is_none());
    runtime.maintenance().await.unwrap();
    assert!(
        runtime
            .storage
            .resolve(&scope, &owner, VALUE_PURPOSE, &backing)
            .await
            .is_err()
    );
    assert!(
        store
            .load(CANDIDATE_KIND, "candidate")
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn legacy_receipts_remain_completed_when_shared_grant_results_are_added() {
    let payload=serde_json::to_vec(&serde_json::json!({"operation":"put","owner":owner(Some(&wire_owner())).unwrap(),"reference":"ref","version":1,"fingerprint":[1],"created_at_ms":1})).unwrap();
    let receipt: Receipt = decode(&payload).unwrap();
    receipt.require_completed().unwrap();
    assert!(receipt.response.is_empty());
    assert_eq!(receipt.result_code, 0);
}

#[tokio::test]
async fn expiration_and_explicit_versions_are_enforced_without_hiding_metadata() {
    let fixture = Fixture::new().await;
    let base = fixture.runtime();
    let runtime = CredentialStoreService::new(
        base.repository.clone(),
        base.storage.clone(),
        base.policy.clone(),
        Duration::from_mins(1),
    )
    .unwrap()
    .runtime;
    let deadline = now_ms().unwrap() + 5000;
    let request = wire::PutSecretRequest {
        expiration_time: Some(openshell_core::time::timestamp_from_millis(deadline).unwrap()),
        ..put()
    };
    let first = runtime
        .clone()
        .put(test_scope(A), request, idempotency("put-one").unwrap())
        .await
        .unwrap();
    let response = runtime
        .resolve(
            &test_scope(A),
            resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery),
        )
        .await
        .unwrap();
    let ttl =
        openshell_core::time::duration_to_std(response.secrets[0].cache_ttl.as_ref().unwrap())
            .unwrap();
    assert!(ttl <= Duration::from_secs(5));
    let mut stale = resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery);
    stale.secrets[0].expected_version = Some(2);
    assert_eq!(
        runtime
            .resolve(&test_scope(A), stale)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let expired = wire::PutSecretRequest {
        reference: first.reference.clone(),
        expected_version: Some(1),
        expiration_time: Some(
            openshell_core::time::timestamp_from_millis(now_ms().unwrap() - 1).unwrap(),
        ),
        idempotency_key: "expired".to_string(),
        ..put()
    };
    runtime
        .clone()
        .put(test_scope(A), expired, idempotency("expired").unwrap())
        .await
        .unwrap();
    assert_eq!(
        runtime
            .resolve(
                &test_scope(A),
                resolve(&first.reference, wire::ResolvePurpose::SandboxDelivery)
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let metadata = runtime
        .resolve(
            &test_scope(A),
            resolve(&first.reference, wire::ResolvePurpose::MetadataInspection),
        )
        .await
        .unwrap();
    assert_eq!(metadata.secrets[0].version, 2);
    assert!(metadata.secrets[0].value.is_empty());
}

#[tokio::test]
async fn reserved_grant_outputs_have_metadata_but_no_readable_fake_values() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let scope = test_scope(A);
    let supplied = owner(Some(&wire_owner())).unwrap();
    let refs = runtime.repository.references(&scope);
    refs.registry()
        .reserve("reserved", &supplied)
        .await
        .unwrap();
    let metadata = runtime
        .resolve(
            &scope,
            resolve("reserved", wire::ResolvePurpose::MetadataInspection),
        )
        .await
        .unwrap();
    assert!(metadata.secrets[0].pending_value);
    assert!(metadata.secrets[0].value.is_empty());
    assert_eq!(metadata.secrets[0].version, 1);
    assert_eq!(
        runtime
            .resolve(
                &scope,
                resolve("reserved", wire::ResolvePurpose::SandboxDelivery)
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), 0);
    let backing = runtime
        .storage
        .stage(&scope, &supplied, VALUE_PURPOSE, "first-mint".to_string())
        .await
        .unwrap();
    refs.registry()
        .replace("reserved", &supplied, 1, backing, None)
        .await
        .unwrap();
    let response = runtime
        .resolve(
            &scope,
            resolve("reserved", wire::ResolvePurpose::SandboxDelivery),
        )
        .await
        .unwrap();
    assert!(!response.secrets[0].pending_value);
    assert_eq!(response.secrets[0].version, 2);
    assert_eq!(response.secrets[0].value, "first-mint");
    assert!(
        refs.load("reserved")
            .await
            .unwrap()
            .unwrap()
            .state
            .pending_deletions
            .is_empty()
    );
}

#[tokio::test]
async fn plaintext_requests_and_forged_headers_never_access_store_operations() {
    let fixture = Fixture::new().await;
    let mut request = Request::new(put());
    request
        .metadata_mut()
        .insert("x-gateway-identity", A.parse().unwrap());
    assert_eq!(
        fixture
            .service
            .put_secret(request)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(
        fixture
            .service
            .get_capabilities(Request::new(wire::GetCapabilitiesRequest {}))
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), 0);
}
