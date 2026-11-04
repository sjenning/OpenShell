// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Selected-issuer tests of the actual SSH consumer, not synthetic publication.
use super::super::{CANDIDATE_TYPE, CREDENTIAL_KEY, OBJECT_TYPE, SshIdentityStore, StoredIdentity};
use super::{authentication, sandbox};
use crate::{
    credential_source::{RemoteProviderSource, tests::issuer::Issuer},
    credentials::CredentialRuntime,
    persistence::{ObjectListQuery, Store},
};
use openshell_core::{
    Config, ObjectId as _,
    proto::{CredentialHandle, credentials::store::v1 as wire},
};
use openshell_credential_issuer::remote_issuer::IssuerChange;
use prost::Message as _;
use std::{sync::Arc, time::Duration};
use tonic::Code;

const INTENT: &str = "credential_issuer_internal_intent_v1";
struct Fixture {
    issuer: Issuer,
    store: Arc<Store>,
    source: RemoteProviderSource,
    runtime: CredentialRuntime,
}
impl Fixture {
    async fn new() -> Self {
        let issuer = Issuer::start().await;
        let store = Arc::new(crate::persistence::test_store().await);
        let source = RemoteProviderSource::new("primary", issuer.watched.clone())
            .unwrap()
            .with_gateway_store(store.clone());
        let runtime = CredentialRuntime::from_issuer(&Config::new(None), source.clone()).unwrap();
        assert!(runtime.issuer_drivers().0.is_empty());
        assert!(
            runtime
                .internal_secrets()
                .stored_credential_count()
                .is_none()
        );
        issuer
            .watched
            .wait_synchronized(Duration::from_secs(5))
            .await
            .unwrap();
        Self {
            issuer,
            store,
            source,
            runtime,
        }
    }
    fn identities(&self) -> SshIdentityStore {
        SshIdentityStore::new(self.store.clone(), self.runtime.internal_secrets())
    }
    async fn reference(&self, sandbox: &openshell_core::proto::Sandbox) -> String {
        let row = self
            .store
            .get(OBJECT_TYPE, &SshIdentityStore::identity_id(sandbox))
            .await
            .unwrap()
            .unwrap();
        assert!(!String::from_utf8_lossy(&row.payload).contains("PRIVATE KEY"));
        let identity: StoredIdentity = serde_json::from_slice(&row.payload).unwrap();
        let handle = CredentialHandle::decode(identity.credential_handle.as_slice()).unwrap();
        let binding: serde_json::Value = serde_json::from_str(&handle.handle).unwrap();
        binding["reference"].as_str().unwrap().to_string()
    }
    async fn metadata(
        &self,
        owner: wire::SecretOwner,
        reference: &str,
    ) -> Result<wire::ResolveSecretsResponse, tonic::Status> {
        self.issuer
            .raw
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: vec![wire::ResolveSecretRequest {
                    owner: Some(owner),
                    request_id: "ssh".into(),
                    reference: reference.into(),
                    expected_version: None,
                }],
            })
            .await
    }
    async fn published_intent(&self, sandbox_id: &str) {
        let page = self
            .store
            .list_object_page(INTENT, ObjectListQuery::AllWorkspaces, None, 128)
            .await
            .unwrap();
        assert_eq!(page.records.len(), 1);
        let state: serde_json::Value = serde_json::from_slice(&page.records[0].payload).unwrap();
        assert_eq!(state["phase"], "published");
        assert_eq!(state["owner"]["kind"], "sandbox");
        assert_eq!(state["owner"]["provider_id"], sandbox_id);
        assert!(!String::from_utf8_lossy(&page.records[0].payload).contains("PRIVATE KEY"));
    }
}
fn typed_owner(sandbox_id: &str) -> wire::SecretOwner {
    wire::SecretOwner {
        workspace: "default".into(),
        credential_key: CREDENTIAL_KEY.into(),
        kind: Some(wire::secret_owner::Kind::Sandbox(
            wire::SandboxSecretOwner {
                sandbox_id: sandbox_id.into(),
            },
        )),
        ..Default::default()
    }
}

#[tokio::test]
async fn selected_issuer_prepares_and_reloads_one_ssh_identity_without_local_drivers() {
    let fixture = Fixture::new().await;
    let mut sandbox = sandbox("issuer-sandbox");
    fixture.store.put_message(&sandbox).await.unwrap();
    let mut first = authentication();
    fixture
        .identities()
        .prepare(&mut sandbox, &mut first)
        .await
        .unwrap();
    let fingerprint = sandbox.host_key_fingerprint.clone();
    assert!(!fingerprint.is_empty());
    let first_key = first
        .supervisor
        .ssh_host_private_key
        .as_ref()
        .unwrap()
        .expose_secret()
        .to_string();
    let reference = fixture.reference(&sandbox).await;
    let metadata = fixture
        .metadata(typed_owner(sandbox.object_id()), &reference)
        .await
        .unwrap();
    assert!(metadata.secrets[0].value.is_empty());
    assert!(!metadata.secrets[0].pending_value);
    let provider_owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: sandbox.object_id().into(),
        credential_key: CREDENTIAL_KEY.into(),
        ..Default::default()
    };
    assert_eq!(
        fixture
            .metadata(provider_owner, &reference)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    fixture.published_intent(sandbox.object_id()).await;
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        0
    );
    fixture
        .issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let mut repeated = authentication();
    fixture
        .identities()
        .prepare(&mut sandbox, &mut repeated)
        .await
        .unwrap();
    assert_eq!(sandbox.host_key_fingerprint, fingerprint);
    assert_eq!(
        repeated
            .supervisor
            .ssh_host_private_key
            .as_ref()
            .unwrap()
            .expose_secret(),
        first_key
    );
    assert_eq!(fixture.reference(&sandbox).await, reference);
    assert!(
        fixture
            .store
            .list_by_scope(CANDIDATE_TYPE, sandbox.object_id(), 128, 0)
            .await
            .unwrap()
            .is_empty()
    );
    fixture.published_intent(sandbox.object_id()).await;
    fixture.identities().delete(&sandbox).await.unwrap();
    assert!(fixture.identities().load(&sandbox).await.unwrap().is_none());
    assert_eq!(
        fixture
            .metadata(typed_owner(sandbox.object_id()), &reference)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn revoked_issuer_ssh_key_is_not_regenerated_or_resolved_locally() {
    let fixture = Fixture::new().await;
    let mut sandbox = sandbox("revoked-issuer-sandbox");
    fixture.store.put_message(&sandbox).await.unwrap();
    fixture
        .identities()
        .prepare(&mut sandbox, &mut authentication())
        .await
        .unwrap();
    let fingerprint = sandbox.host_key_fingerprint.clone();
    let reference = fixture.reference(&sandbox).await;
    let mut changes = fixture.issuer.watched.changes();
    fixture
        .issuer
        .raw
        .delete_secret(wire::DeleteSecretRequest {
            owner: Some(typed_owner(sandbox.object_id())),
            reference: reference.clone(),
            expected_version: None,
            idempotency_key: "revoke-published-ssh".into(),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(changes.recv().await.unwrap(), IssuerChange::Secret { reference: observed, revoked: true, .. } if observed == reference) {
                break;
            }
        }
    }).await.unwrap();
    fixture
        .issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(
        fixture
            .identities()
            .prepare(&mut sandbox, &mut authentication())
            .await
            .is_err()
    );
    assert_eq!(sandbox.host_key_fingerprint, fingerprint);
    assert_eq!(fixture.reference(&sandbox).await, reference);
    fixture.published_intent(sandbox.object_id()).await;
    assert!(fixture.runtime.issuer_drivers().0.is_empty());
}
