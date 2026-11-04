// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::{
    SSH_CANDIDATE, SSH_KEY, SUPERVISOR_CANDIDATE, SUPERVISOR_KEY, intent, owner, register_existing,
};
use crate::{
    credential_source::{RemoteProviderSource, tests::issuer::Issuer, wire},
    credentials::InternalSecretOwner,
    persistence::{AtomicWrite, ObjectListQuery, Store, WriteCondition},
};
use openshell_core::proto::{CredentialHandle, ObjectMeta, Sandbox};
use openshell_credential_issuer::SecretOwnerKind;
use prost::Message as _;
use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};
use tonic::{Code, Status};

struct Fixture {
    issuer: Issuer,
    store: Arc<Store>,
    source: RemoteProviderSource,
}
impl Fixture {
    async fn new() -> Self {
        let issuer = Issuer::start().await;
        let store = Arc::new(crate::persistence::test_store().await);
        let source = RemoteProviderSource::new("primary", issuer.watched.clone())
            .unwrap()
            .with_gateway_store(store.clone());
        Self {
            issuer,
            store,
            source,
        }
    }
    async fn stage(&self, operation: &str) -> HashMap<String, CredentialHandle> {
        self.source
            .store_internal(
                identity(),
                operation,
                &HashMap::from([(SSH_KEY.into(), "private-host-key".into())]),
            )
            .await
            .unwrap()
    }
    async fn candidate(
        &self,
        operation: &str,
        handles: &HashMap<String, CredentialHandle>,
        scope: &str,
    ) {
        let payload = serde_json::to_vec(&serde_json::json!({"fingerprint":"public-fingerprint", "credential_handle":handles[SSH_KEY].encode_to_vec()})).unwrap();
        self.store
            .create_scoped(
                SSH_CANDIDATE,
                operation,
                operation,
                "default",
                scope,
                &payload,
                None,
            )
            .await
            .unwrap();
    }
    async fn value(
        &self,
        identity: InternalSecretOwner<'_>,
        key: &str,
        handle: &CredentialHandle,
    ) -> Result<String, Status> {
        let binding = self.source.decode(handle).unwrap();
        self.issuer
            .raw
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::SandboxDelivery as i32,
                secrets: vec![wire::ResolveSecretRequest {
                    request_id: "request".into(),
                    owner: Some(owner(identity, key).unwrap()),
                    reference: binding.reference,
                    expected_version: None,
                }],
            })
            .await
            .map(|response| response.secrets[0].value.clone())
    }
    async fn journal(&self) -> crate::persistence::ObjectRecord {
        self.store
            .list_object_page(intent::KIND, ObjectListQuery::AllWorkspaces, None, 128)
            .await
            .unwrap()
            .records
            .remove(0)
    }
    async fn publication(
        &self,
        operation: &str,
        handles: &HashMap<String, CredentialHandle>,
    ) -> Vec<AtomicWrite> {
        let mut writes = self
            .source
            .internal_publication_writes(identity(), operation, operation, handles)
            .await
            .unwrap();
        writes.push(AtomicWrite::Create {
            object_type:"sandbox_ssh_identity_v1".into(), id:format!("sandbox-ssh:{}", identity().id),
            name:identity().id.into(), workspace:"default".into(),
            payload:serde_json::to_vec(&serde_json::json!({"fingerprint":"public-fingerprint", "credential_handle":handles[SSH_KEY].encode_to_vec()})).unwrap(),
        });
        writes
    }
}
fn identity() -> InternalSecretOwner<'static> {
    InternalSecretOwner {
        kind: SecretOwnerKind::Sandbox,
        name: "display",
        workspace: "default",
        id: "sandbox-owner",
    }
}
#[tokio::test]
async fn closing_cas_fences_even_a_prepared_late_native_publication() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("candidate").await;
    fixture
        .candidate("candidate", &handles, identity().id)
        .await;
    let writes = fixture.publication("candidate", &handles).await;
    let page = fixture
        .source
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(page.cleaned, 1);
    assert!(fixture.store.write_atomically(&writes).await.is_err());
    assert!(
        fixture
            .store
            .get("sandbox_ssh_identity_v1", "sandbox-ssh:sandbox-owner")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handles[SSH_KEY])
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert!(
        fixture
            .source
            .store_internal(
                identity(),
                "candidate",
                &HashMap::from([(SSH_KEY.into(), "different-private".into())])
            )
            .await
            .is_err()
    );
    let row = fixture.journal().await;
    let payload = String::from_utf8(row.payload).unwrap();
    assert!(payload.contains("\"phase\":\"closed\""));
    assert!(!payload.contains("private-host-key"));
    assert!(!payload.contains(&fixture.source.decode(&handles[SSH_KEY]).unwrap().reference));
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        0
    );
}
#[tokio::test]
async fn successful_native_publication_transfers_ownership_and_survives_collection() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("published").await;
    fixture
        .candidate("published", &handles, identity().id)
        .await;
    let writes = fixture.publication("published", &handles).await;
    fixture.store.write_atomically(&writes).await.unwrap();
    let page = fixture
        .source
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(page.cleaned, 0);
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handles[SSH_KEY])
            .await
            .unwrap(),
        "private-host-key"
    );
    assert!(
        String::from_utf8(fixture.journal().await.payload)
            .unwrap()
            .contains("\"phase\":\"published\"")
    );
}
#[tokio::test]
async fn lost_reservation_ack_is_recovered_and_stale_bind_cannot_fill() {
    let fixture = Fixture::new().await;
    let values = HashMap::from([(SSH_KEY.into(), "private-host-key".into())]);
    let mut intent = intent::Intent::begin(&fixture.source, identity(), "lost", &values)
        .await
        .unwrap();
    let key = intent::reservation_key(identity(), "lost", SSH_KEY).unwrap();
    let reserved = fixture
        .source
        .client
        .reserve_secret(wire::ReserveSecretRequest {
            owner: Some(owner(identity(), SSH_KEY).unwrap()),
            idempotency_key: format!("internal-reserve:{key}"),
        })
        .await
        .unwrap();
    let page = fixture
        .source
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(page.cleaned, 1);
    assert_eq!(
        intent
            .bind(SSH_KEY, &reserved.reference)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let put = fixture
        .issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner(identity(), SSH_KEY).unwrap()),
            reference: reserved.reference,
            value: "late-private-value".into(),
            expected_version: Some(1),
            idempotency_key: "late-fill".into(),
            ..Default::default()
        })
        .await;
    assert!(put.is_err());
}
#[tokio::test]
async fn recent_foreign_and_unfenced_legacy_intents_are_not_collected() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("recent").await;
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, 0)
            .await
            .unwrap()
            .cleaned,
        0
    );
    let other = RemoteProviderSource::new("other", fixture.issuer.watched.clone())
        .unwrap()
        .with_gateway_store(fixture.store.clone());
    assert_eq!(
        other
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        0
    );
    let row = fixture.journal().await;
    let mut value: serde_json::Value = serde_json::from_slice(&row.payload).unwrap();
    value.as_object_mut().unwrap().remove("format");
    value.as_object_mut().unwrap().remove("phase");
    fixture
        .store
        .put_if(
            intent::KIND,
            &row.id,
            &row.name,
            &row.workspace,
            &serde_json::to_vec(&value).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(row.resource_version),
        )
        .await
        .unwrap();
    let page = fixture
        .source
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(page.legacy_retained, 1);
    assert_eq!(page.cleaned, 0);
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handles[SSH_KEY])
            .await
            .unwrap(),
        "private-host-key"
    );
}
#[tokio::test]
async fn publication_requires_exact_candidate_scope_and_reference() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("wrong-scope").await;
    fixture
        .candidate("wrong-scope", &handles, "different-sandbox")
        .await;
    assert!(
        fixture
            .source
            .internal_publication_writes(identity(), "wrong-scope", "wrong-scope", &handles)
            .await
            .is_err()
    );
    let handles2 = fixture.stage("other-candidate").await;
    fixture
        .candidate("other-candidate", &handles2, identity().id)
        .await;
    assert!(
        fixture
            .source
            .internal_publication_writes(identity(), "wrong-scope", "other-candidate", &handles)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn remote_inventory_registers_ssh_candidates_using_scope_not_candidate_name() {
    let fixture = Fixture::new().await;
    fixture
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: identity().id.into(),
                name: "sandbox-name".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let handles = fixture.stage("unrelated-candidate-name").await;
    fixture
        .candidate("unrelated-candidate-name", &handles, identity().id)
        .await;
    let before = fixture.issuer.resolves.load(Ordering::SeqCst);
    register_existing(&fixture.store, &fixture.source)
        .await
        .unwrap();
    assert_eq!(fixture.issuer.resolves.load(Ordering::SeqCst), before);
    fixture
        .source
        .client
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        fixture
            .source
            .client
            .known_secret(
                &owner(identity(), SSH_KEY).unwrap(),
                &fixture.source.decode(&handles[SSH_KEY]).unwrap().reference
            )
            .is_ok()
    );
}
#[tokio::test]
async fn remote_inventory_does_not_silently_skip_unattributable_or_legacy_candidates() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("orphan-candidate").await;
    fixture
        .candidate("orphan-candidate", &handles, identity().id)
        .await;
    register_existing(&fixture.store, &fixture.source)
        .await
        .unwrap();
    fixture
        .candidate("unattributable-candidate", &handles, identity().id)
        .await;
    assert_eq!(
        register_existing(&fixture.store, &fixture.source)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    fixture
        .store
        .delete(SSH_CANDIDATE, "unattributable-candidate")
        .await
        .unwrap();
    fixture
        .store
        .put_message(&Sandbox {
            metadata: Some(ObjectMeta {
                id: identity().id.into(),
                name: "sandbox-name".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();
    let legacy = CredentialHandle {
        driver: "legacy-db".into(),
        handle: "private-legacy-handle".into(),
        ..Default::default()
    };
    fixture
        .candidate(
            "legacy-candidate",
            &HashMap::from([(SSH_KEY.into(), legacy)]),
            identity().id,
        )
        .await;
    let error = register_existing(&fixture.store, &fixture.source)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(!format!("{error:?}").contains("private-legacy-handle"));
}
#[tokio::test]
async fn closing_recovery_resumes_without_waiting_for_a_new_timeout() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("crashed-cleaner").await;
    let row = fixture.journal().await;
    let mut payload: serde_json::Value = serde_json::from_slice(&row.payload).unwrap();
    payload["phase"] = "closing".into();
    fixture
        .store
        .put_if(
            intent::KIND,
            &row.id,
            &row.name,
            &row.workspace,
            &serde_json::to_vec(&payload).unwrap(),
            None,
            WriteCondition::MatchResourceVersion(row.resource_version),
        )
        .await
        .unwrap();
    let reopened = RemoteProviderSource::new("primary", fixture.issuer.watched.clone())
        .unwrap()
        .with_gateway_store(fixture.store.clone());
    assert_eq!(
        reopened
            .recover_internal_page(None, 32, 0)
            .await
            .unwrap()
            .cleaned,
        1
    );
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handles[SSH_KEY])
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
#[tokio::test]
async fn recovery_keeps_the_raw_cursor_and_bounds_each_page() {
    let fixture = Fixture::new().await;
    fixture.stage("first").await;
    fixture.stage("second").await;
    let first = fixture
        .source
        .recover_internal_page(None, 1, i64::MAX)
        .await
        .unwrap();
    assert_eq!((first.scanned, first.cleaned), (1, 1));
    let second = fixture
        .source
        .recover_internal_page(first.next_cursor.as_ref(), 1, i64::MAX)
        .await
        .unwrap();
    assert_eq!((second.scanned, second.cleaned), (1, 1));
    assert!(
        fixture
            .source
            .recover_internal_page(None, 129, i64::MAX)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn supervisor_reservation_publication_uses_the_same_native_fence() {
    let fixture = Fixture::new().await;
    let identity = InternalSecretOwner {
        kind: SecretOwnerKind::SupervisorInstance,
        id: "instance-route",
        ..identity()
    };
    let handles = fixture
        .source
        .store_internal(
            identity,
            "reservation-writer",
            &HashMap::from([(SUPERVISOR_KEY.into(), "private-launch-material".into())]),
        )
        .await
        .unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"route":identity.id,"workspace":identity.workspace,"writer":"reservation-writer","material_handle":handles[SUPERVISOR_KEY].encode_to_vec()})).unwrap();
    fixture
        .store
        .put_if(
            SUPERVISOR_CANDIDATE,
            "different-candidate-id",
            "different-candidate-id",
            "",
            &payload,
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();
    fixture
        .store
        .put_if(
            "supervisor_instance_assignment",
            "reservation",
            "instance-route",
            "",
            b"{}",
            None,
            WriteCondition::MustCreate,
        )
        .await
        .unwrap();
    let mut writes = fixture
        .source
        .internal_publication_writes(
            identity,
            "reservation-writer",
            "different-candidate-id",
            &handles,
        )
        .await
        .unwrap();
    writes.push(AtomicWrite::Update {
        object_type: "supervisor_instance_assignment".into(),
        id: "reservation".into(),
        expected_version: 1,
        payload,
    });
    fixture
        .source
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert!(fixture.store.write_atomically(&writes).await.is_err());
    assert_eq!(
        fixture
            .value(identity, SUPERVISOR_KEY, &handles[SUPERVISOR_KEY])
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
