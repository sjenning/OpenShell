// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    auth::{GatewayPolicy, test_scope},
    backend::CredentialDriver,
    minter::{
        MaterialDescriptor, MintFailure, MintRequest, MintResponse, RetrySchedule,
        StrategyDescriptor, TokenMinter,
    },
    repository::Repository,
    storage::CredentialStorage,
};
use openshell_core::proto::{
    CredentialHandle,
    credentials::store::v1 as store_wire,
    credentials::v1::{
        DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential,
        StoreCredentialRequest,
    },
};
use openshell_driver_db_credstore::{
    DbCredstoreCredentialDriver, EncryptedGatewayCredentialStoreCrypto,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

mod mtls;
mod postgres;
mod recovery;
mod remote_client;
mod watched_client;

const A: &str = "spiffe://test.example/gateway/a";
const B: &str = "spiffe://test.example/gateway/b";
#[derive(Debug)]
struct Driver {
    inner: DbCredstoreCredentialDriver,
    fail: Arc<AtomicBool>,
    resolves: Arc<AtomicUsize>,
    fail_resolves: Arc<AtomicBool>,
}
#[tonic::async_trait]
impl CredentialDriver for Driver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::unavailable("private-backend-error"));
        }
        self.inner.store_credential(request).await
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }
    async fn resolve_credentials(
        &self,
        request: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.resolves.fetch_add(request.len(), Ordering::SeqCst);
        if self.fail_resolves.load(Ordering::SeqCst) {
            return Err(Status::unavailable("private-resolve-error"));
        }
        self.inner.resolve_credentials(request).await
    }
}
#[derive(Debug, Default)]
struct Minter {
    calls: AtomicUsize,
    seen: Mutex<Vec<String>>,
    block: AtomicBool,
    uncertain: AtomicBool,
    oauth_uncertain: AtomicBool,
    fail_backend: AtomicBool,
    backend: Arc<AtomicBool>,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:test".into(),
            config: vec![MaterialDescriptor {
                name: "audience".into(),
                required: true,
            }],
            secret_material: vec![MaterialDescriptor {
                name: "refresh_token".into(),
                required: true,
            }],
            outputs: vec!["first".into(), "second".into()],
            rotated_secret_material: vec!["refresh_token".into()],
        }
    }
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.seen
            .lock()
            .unwrap()
            .push(request.secret_material["refresh_token"].clone());
        if self.block.swap(false, Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        if self.uncertain.load(Ordering::SeqCst) {
            return Err(MintFailure {
                status: Status::failed_precondition("private-minter-error"),
                recovery_action: if self.oauth_uncertain.load(Ordering::SeqCst) {
                    RecoveryAction::Reauthorize
                } else {
                    RecoveryAction::Investigate
                },
                failure_code: if self.oauth_uncertain.load(Ordering::SeqCst) {
                    "oauth_refresh_exchange_uncertain"
                } else {
                    "test_outcome_unknown"
                },
                provider_error_subtype: None,
                retry_schedule: RetrySchedule::Parked,
            });
        }
        if self.fail_backend.swap(false, Ordering::SeqCst) {
            self.backend.store(true, Ordering::SeqCst);
        }
        Ok(MintResponse {
            outputs: HashMap::from([
                ("first".into(), format!("first-{count}")),
                ("second".into(), format!("second-{count}")),
            ]),
            expiration_time_ms: now_ms().unwrap() + 60_000,
            rotated_secret_material: HashMap::from([(
                "refresh_token".into(),
                format!("rotated-{count}"),
            )]),
        })
    }
}
struct Fixture {
    service: CredentialRefreshService,
    store: CredentialStoreService,
    minter: Arc<Minter>,
    resolves: Arc<AtomicUsize>,
    fail_resolves: Arc<AtomicBool>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(directory.path().join("key").to_str().unwrap().into()),
        )]);
        let fail = Arc::new(AtomicBool::new(false));
        let resolves = Arc::new(AtomicUsize::new(0));
        let fail_resolves = Arc::new(AtomicBool::new(false));
        let driver: Arc<dyn CredentialDriver> = Arc::new(Driver {
            inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
            fail: fail.clone(),
            resolves: resolves.clone(),
            fail_resolves: fail_resolves.clone(),
        });
        let storage =
            CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
        let policy = GatewayPolicy::new(BTreeMap::from([
            (A.into(), vec!["default".into()]),
            (B.into(), vec!["default".into()]),
        ]))
        .unwrap();
        let store =
            CredentialStoreService::new(repository, storage, policy, Duration::from_secs(2))
                .unwrap();
        let minter = Arc::new(Minter {
            backend: fail,
            ..Minter::default()
        });
        let mut registry = MinterRegistry::default();
        registry.register_custom(minter.clone()).unwrap();
        let service = CredentialRefreshService::new(
            &store,
            Arc::new(registry),
            MintResultSpool::new(
                EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap(),
            ),
        )
        .unwrap();
        Self {
            service,
            store,
            minter,
            resolves,
            fail_resolves,
            _directory: directory,
        }
    }
    fn runtime(&self) -> Arc<GrantRuntime> {
        self.service.runtime.clone()
    }
}
fn owner() -> store_wire::SecretOwner {
    store_wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN_ONE".into(),
        provider: "display".into(),
    }
}
fn request() -> wire::CreateGrantRequest {
    wire::CreateGrantRequest {
        owner: Some(owner()),
        strategy: "custom:test".into(),
        config: HashMap::from([("audience".into(), "private-audience".into())]),
        secret_material: HashMap::from([("refresh_token".into(), "initial-refresh".into())]),
        outputs: HashMap::from([
            ("first".into(), "TOKEN_ONE".into()),
            ("second".into(), "TOKEN_TWO".into()),
        ]),
        refresh_before: Some(openshell_core::time::duration_from_std(Duration::ZERO).unwrap()),
        max_lifetime: Some(
            openshell_core::time::duration_from_std(Duration::from_mins(2)).unwrap(),
        ),
        idempotency_key: "create".into(),
    }
}
async fn create(fixture: &Fixture) -> wire::CreateGrantResponse {
    fixture
        .runtime()
        .create(test_scope(A), request(), idempotency("create").unwrap())
        .await
        .unwrap()
}
async fn values(
    fixture: &Fixture,
    result: &wire::CreateGrantResponse,
) -> store_wire::ResolveSecretsResponse {
    let secrets = [("first", "TOKEN_ONE"), ("second", "TOKEN_TWO")]
        .into_iter()
        .map(|(name, key)| store_wire::ResolveSecretRequest {
            request_id: name.into(),
            owner: Some(store_wire::SecretOwner {
                credential_key: key.into(),
                ..owner()
            }),
            reference: result.output_references[name].clone(),
            expected_version: None,
        })
        .collect();
    fixture
        .store
        .runtime
        .resolve(
            &test_scope(A),
            store_wire::ResolveSecretsRequest {
                secrets,
                purpose: store_wire::ResolvePurpose::SandboxDelivery as i32,
            },
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn create_reserves_fixed_outputs_then_mints_rotates_and_replays_original_results() {
    let fixture = Fixture::new().await;
    let result = create(&fixture).await;
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
    let repeated = create(&fixture).await;
    assert_eq!(result, repeated);
    assert!(
        fixture
            .runtime()
            .load(&test_scope(B), &result.grant)
            .await
            .is_err()
    );
    let status = fixture
        .runtime()
        .ensure(test_scope(A), result.grant.clone(), 0)
        .await
        .unwrap();
    assert_eq!(status.state, "refreshed");
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    let first = values(&fixture, &result).await;
    assert!(first.secrets.iter().all(|secret| secret.version == 2));
    assert_eq!(first.secrets[0].value, "first-1");
    fixture
        .runtime()
        .ensure(test_scope(A), result.grant.clone(), 0)
        .await
        .unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    let rotation = fixture
        .runtime()
        .rotate(
            test_scope(A),
            result.grant.clone(),
            idempotency("rotate").unwrap(),
        )
        .await
        .unwrap();
    let replay = fixture
        .runtime()
        .rotate(
            test_scope(A),
            result.grant.clone(),
            idempotency("rotate").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rotation, replay);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *fixture.minter.seen.lock().unwrap(),
        vec!["initial-refresh", "rotated-1"]
    );
    let second = values(&fixture, &result).await;
    assert!(second.secrets.iter().all(|secret| secret.version == 3));
    assert_eq!(second.secrets[0].value, "first-2");
    assert_eq!(result.output_references, repeated.output_references);
    fixture
        .runtime()
        .delete(
            test_scope(A),
            result.grant.clone(),
            idempotency("delete").unwrap(),
        )
        .await
        .unwrap();
    assert!(
        fixture
            .runtime()
            .ensure(test_scope(A), result.grant.clone(), 0)
            .await
            .is_err()
    );
    fixture.runtime().tick().await.unwrap();
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &result.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Deleted
    );
    fixture
        .runtime()
        .delete(test_scope(A), result.grant, idempotency("delete").unwrap())
        .await
        .unwrap();
}
