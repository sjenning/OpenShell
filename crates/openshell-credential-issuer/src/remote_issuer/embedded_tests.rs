// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    auth::GatewayPolicy,
    backend::CredentialDriver,
    mint_spool::MintResultSpool,
    minter::MinterRegistry,
    repository::Repository,
    service::{CredentialRefreshService, CredentialStoreService},
    storage::CredentialStorage,
};
use openshell_driver_db_credstore::{
    DbCredstoreCredentialDriver, EncryptedGatewayCredentialStoreCrypto,
};
use std::collections::BTreeMap;
use store::credential_store_server::CredentialStore as _;
use tonic::Code;

mod grants;

struct Fixture {
    store: CredentialStoreService,
    refresh: CredentialRefreshService,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        Self::with_minters(MinterRegistry::default()).await
    }
    async fn with_minters(minters: MinterRegistry) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(directory.path().join("key").display().to_string()),
        )]);
        let driver: Arc<dyn CredentialDriver> = Arc::new(
            DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
        );
        let storage =
            CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
        let store =
            CredentialStoreService::embedded(repository, storage, Duration::from_secs(30)).unwrap();
        let refresh = CredentialRefreshService::new(
            &store,
            Arc::new(minters),
            MintResultSpool::new(
                EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap(),
            ),
        )
        .unwrap();
        Self {
            store,
            refresh,
            _directory: directory,
        }
    }
    async fn client(&self) -> RemoteIssuer {
        RemoteIssuer::embedded(self.store.clone(), self.refresh.clone())
            .await
            .unwrap()
    }
}
fn owner() -> store::SecretOwner {
    store::SecretOwner {
        workspace: "new-workspace-not-in-operator-config".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    }
}
fn put() -> store::PutSecretRequest {
    store::PutSecretRequest {
        owner: Some(owner()),
        value: "private-value".into(),
        idempotency_key: "put".into(),
        ..Default::default()
    }
}
fn resolve(reference: &str) -> store::ResolveSecretsRequest {
    store::ResolveSecretsRequest {
        secrets: vec![store::ResolveSecretRequest {
            request_id: "one".into(),
            reference: reference.into(),
            owner: Some(owner()),
            expected_version: None,
        }],
        purpose: store::ResolvePurpose::SandboxDelivery as i32,
    }
}

#[tokio::test]
async fn embedded_reuses_hosted_ownership_versioning_idempotency_and_size_checks() {
    let fixture = Fixture::new().await;
    let client = fixture.client().await;
    let created = client.put_secret(put()).await.unwrap();
    assert_eq!(created.version, 1);
    assert_eq!(client.put_secret(put()).await.unwrap(), created);
    let mut conflicting = put();
    conflicting.value = "different".into();
    assert_eq!(
        client.put_secret(conflicting).await.unwrap_err().code(),
        Code::AlreadyExists
    );
    let result = client
        .resolve_secrets(resolve(&created.reference))
        .await
        .unwrap();
    assert_eq!(result.secrets[0].value, "private-value");
    assert_eq!(result.secrets[0].version, 1);
    let mut wrong_owner = resolve(&created.reference);
    wrong_owner.secrets[0].owner.as_mut().unwrap().provider_id = "other-provider".into();
    assert_eq!(
        client
            .resolve_secrets(wrong_owner)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let mut oversized = put();
    oversized.value = "x".repeat(LIMIT);
    assert_eq!(
        client.put_secret(oversized).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        client
            .put_secret(store::PutSecretRequest {
                reference: created.reference.clone(),
                expected_version: Some(2),
                idempotency_key: "stale".into(),
                ..put()
            })
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let updated = client
        .put_secret(store::PutSecretRequest {
            reference: created.reference.clone(),
            expected_version: Some(1),
            idempotency_key: "update".into(),
            value: "replacement".into(),
            ..put()
        })
        .await
        .unwrap();
    assert_eq!(updated.reference, created.reference);
    assert_eq!(updated.version, 2);
    let removed = client
        .delete_secret(store::DeleteSecretRequest {
            reference: created.reference.clone(),
            owner: Some(owner()),
            expected_version: Some(2),
            idempotency_key: "delete".into(),
        })
        .await
        .unwrap();
    assert_eq!(removed.version, 3);
    assert_eq!(
        client
            .resolve_secrets(resolve(&created.reference))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn embedded_scope_is_fixed_and_typed_not_a_header_or_remote_wildcard_bypass() {
    let fixture = Fixture::new().await;
    let mut request = Request::new(store::GetCapabilitiesRequest {});
    request.metadata_mut().insert(
        "x-gateway-identity",
        "spiffe://openshell.local/gateway/embedded".parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("x-openshell-embedded", "true".parse().unwrap());
    assert_eq!(
        fixture
            .store
            .get_capabilities(request)
            .await
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    let policy = GatewayPolicy::new(BTreeMap::from([(
        "spiffe://example.test/gateway".into(),
        vec!["default".into()],
    )]))
    .unwrap();
    assert_eq!(
        policy
            .authenticate(&crate::auth::local_request(Request::new(())))
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        GatewayPolicy::new(BTreeMap::from([(
            "spiffe://example.test/gateway".into(),
            vec!["*".into()]
        )]))
        .is_err()
    );
    let client = fixture.client().await;
    for workspace in ["", "*", " leading", "trailing ", "new\nworkspace"] {
        let mut message = put();
        message.owner.as_mut().unwrap().workspace = workspace.into();
        assert_eq!(
            client.put_secret(message).await.unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    // Reconstructing a typed client cannot choose a new local identity.
    let first = client.put_secret(put()).await.unwrap();
    assert_eq!(
        fixture.client().await.put_secret(put()).await.unwrap(),
        first
    );
    assert_eq!(
        fixture.store.embedded_scope().unwrap().identity(),
        "spiffe://openshell.local/gateway/embedded"
    );
    let scopes = GatewayPolicy::embedded()
        .unwrap()
        .configured_scopes()
        .unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(
        scopes[0].identity(),
        "spiffe://openshell.local/gateway/embedded"
    );
    assert!(
        scopes[0]
            .authorize_workspace("later-created-workspace")
            .is_ok()
    );
}

#[tokio::test]
async fn embedded_typed_internal_owners_never_alias_provider_values() {
    use store::secret_owner::Kind;
    let fixture = Fixture::new().await;
    let client = fixture.client().await;
    let provider = client.put_secret(put()).await.unwrap();
    let sandbox_owner = store::SecretOwner {
        provider_id: String::new(),
        kind: Some(Kind::Sandbox(store::SandboxSecretOwner {
            sandbox_id: "provider".into(),
        })),
        ..owner()
    };
    let sandbox = client
        .put_secret(store::PutSecretRequest {
            owner: Some(sandbox_owner.clone()),
            idempotency_key: "sandbox".into(),
            value: "sandbox-value".into(),
            ..put()
        })
        .await
        .unwrap();
    let mut request = resolve(&sandbox.reference);
    request.secrets[0].owner = Some(sandbox_owner.clone());
    assert_eq!(
        client.resolve_secrets(request).await.unwrap().secrets[0].value,
        "sandbox-value"
    );
    assert_eq!(
        client
            .resolve_secrets(resolve(&provider.reference))
            .await
            .unwrap()
            .secrets[0]
            .value,
        "private-value"
    );
    let mut forged = resolve(&provider.reference);
    forged.secrets[0].owner = Some(sandbox_owner);
    assert_eq!(
        client.resolve_secrets(forged).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}

#[tokio::test]
async fn embedded_watched_cache_observes_mutations_from_another_client_and_fails_closed() {
    let fixture = Fixture::new().await;
    let writer = fixture.client().await;
    let source = WatchedIssuer::new(fixture.client().await);
    source
        .wait_synchronized(Duration::from_secs(3))
        .await
        .unwrap();
    let created = source.put_secret(put()).await.unwrap();
    let mut initial_request = resolve(&created.reference);
    initial_request.secrets[0].expected_version = Some(1);
    let first = source
        .resolve_secrets(initial_request.clone())
        .await
        .unwrap();
    assert_eq!(first.secrets[0].value, "private-value");
    assert_eq!(
        source
            .resolve_secrets(initial_request)
            .await
            .unwrap()
            .secrets[0]
            .value,
        "private-value"
    );
    let mut changes = source.changes();
    writer
        .put_secret(store::PutSecretRequest {
            reference: created.reference.clone(),
            expected_version: Some(1),
            value: "replacement".into(),
            idempotency_key: "other-client-update".into(),
            ..put()
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if matches!(changes.recv().await.unwrap(), IssuerChange::Secret { reference, version: 2, .. } if reference == created.reference) {
                break;
            }
        }
    }).await.unwrap();
    let second = source
        .resolve_secrets(resolve(&created.reference))
        .await
        .unwrap();
    assert_eq!(second.secrets[0].value, "replacement");
    assert_eq!(second.secrets[0].version, 2);
    fixture.store.stop_admission();
    let mut health = source.health_changes();
    tokio::time::timeout(Duration::from_secs(3), async {
        while health.borrow_and_update().synchronized() {
            health.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(
        source
            .known_secret(&owner(), &created.reference)
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    // Direct authenticated reads may still succeed while watch recovery is in
    // progress, but an unknown watch epoch must never issue a cacheable value.
    let mut request = resolve(&created.reference);
    request.secrets[0].expected_version = Some(2);
    let uncached = source.resolve_secrets(request).await.unwrap();
    assert_eq!(uncached.secrets[0].value, "replacement");
    assert_eq!(
        uncached.secrets[0].cache_ttl,
        Some(prost_types::Duration::default())
    );
}

#[tokio::test]
async fn embedded_watch_shares_capacity_and_shutdown_fences() {
    let fixture = Fixture::new().await;
    let client = fixture.client().await;
    let mut secrets = client.watch_secrets(0).await.unwrap();
    let mut grants = client.watch_grants(0).await.unwrap();
    assert!(secrets.message().await.unwrap().unwrap().reset_required);
    assert!(grants.message().await.unwrap().unwrap().reset_required);
    assert_eq!(client.watches.available_permits(), 0);
    drop(grants);
    assert_eq!(client.watches.available_permits(), 1);
    fixture.store.stop_admission();
    tokio::time::timeout(Duration::from_secs(1), async {
        while secrets.message().await.unwrap().is_some() {}
    })
    .await
    .unwrap();
    assert!(secrets.message().await.unwrap().is_none());
    assert_eq!(
        client.watch_grants(0).await.unwrap_err().code(),
        Code::Unavailable
    );
}

#[tokio::test]
async fn embedded_refresh_uses_the_generated_refresh_handlers() {
    let fixture = Fixture::new().await;
    let client = fixture.client().await;
    let strategies = client.list_strategies().await.unwrap();
    assert!(strategies.strategies.is_empty());
    assert!(strategies.supports_pending_reservations);
    assert_eq!(
        client
            .get_grant(refresh::GetGrantRequest {
                grant: "missing".into()
            })
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        client
            .get_grant(refresh::GetGrantRequest {
                grant: String::new()
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
}
