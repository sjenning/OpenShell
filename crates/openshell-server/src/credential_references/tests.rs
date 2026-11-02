// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::ObjectMeta;
use std::sync::atomic::{AtomicBool, Ordering};

#[path = "tests/batches.rs"]
mod batches;

#[derive(Debug)]
struct LostAcknowledgement {
    database: DatabaseReferences,
    fail_once: AtomicBool,
    fail_observation: AtomicBool,
    suppress_observation: bool,
}

#[async_trait]
impl ReferenceStateStore for LostAcknowledgement {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        if self.fail_observation.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("injected observation outage"));
        }
        self.database.load(reference).await
    }
    async fn compare_and_swap(
        &self,
        reference: &str,
        revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        self.database
            .compare_and_swap(reference, revision, state)
            .await?;
        if state.version == 2 && self.fail_once.swap(false, Ordering::SeqCst) {
            self.fail_observation
                .store(self.suppress_observation, Ordering::SeqCst);
            return Err(Status::unavailable("injected lost commit acknowledgement"));
        }
        Ok(())
    }
}

fn provider(handles: HashMap<String, CredentialHandle>) -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider-id".into(),
            name: "provider".into(),
            workspace: "workspace".into(),
            resource_version: 7,
            ..Default::default()
        }),
        credential_handles: handles,
        ..Default::default()
    }
}

async fn write(runtime: &CredentialRuntime) -> Provider {
    let handles = runtime
        .store_provider_credentials(
            "provider",
            "workspace",
            "provider-id",
            &HashMap::from([("API_KEY".into(), "first-value".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    provider(handles)
}

#[tokio::test]
async fn uncertain_commit_never_deletes_a_published_candidate() {
    for suppress_observation in [false, true] {
        let store = Arc::new(crate::persistence::test_store().await);
        let mut runtime =
            CredentialRuntime::from_config_with_store(&Config::new(None), store.clone()).unwrap();
        let provider = write(&runtime).await;
        runtime.references = Some(Arc::new(ReferenceRegistry::new(Arc::new(
            LostAcknowledgement {
                database: DatabaseReferences(store.clone()),
                fail_once: AtomicBool::new(true),
                fail_observation: AtomicBool::new(false),
                suppress_observation,
            },
        ))));
        let result = runtime
            .rotate_provider_reference(
                provider_scope(&provider, "API_KEY"),
                &provider.credential_handles["API_KEY"],
                1,
                "second-value",
                None,
            )
            .await;
        if suppress_observation {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        } else {
            assert_eq!(result.unwrap(), 2);
        }
        let current = runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap();
        assert_eq!(current.values["API_KEY"], "second-value");
        assert_eq!(current.versions["API_KEY"], 2);
        let record = store
            .get(
                OBJECT_TYPE,
                &reference_key(&provider.credential_handles["API_KEY"]).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let payload = String::from_utf8(record.payload).unwrap();
        assert!(!payload.contains("first-value"));
        assert!(!payload.contains("second-value"));
        runtime
            .delete_provider_credential_handles(
                "provider",
                "workspace",
                "provider-id",
                &provider.credential_handles,
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn stable_reference_rotates_and_survives_runtime_reconstruction() {
    let store = Arc::new(crate::persistence::test_store().await);
    let config = Config::new(None);
    let runtime = CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap();
    let mut notifications = runtime.reference_changes.subscribe();
    let provider = write(&runtime).await;
    let before = provider.clone();
    let key = &provider.credential_handles["API_KEY"];
    assert_eq!(versions(&store, &provider).await.unwrap()["API_KEY"], 1);
    assert_eq!(
        runtime
            .rotate_provider_reference(
                provider_scope(&provider, "API_KEY"),
                key,
                1,
                "second-value",
                Some(5000)
            )
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        notifications.try_recv().unwrap(),
        ("workspace".into(), "provider".into())
    );
    assert_eq!(
        provider, before,
        "rotation must not mutate the provider record or reference identity"
    );
    let restarted = CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap();
    let resolved = restarted
        .resolve_provider_handles(&provider, 1000)
        .await
        .unwrap();
    assert_eq!(resolved.values["API_KEY"], "second-value");
    assert_eq!(resolved.versions["API_KEY"], 2);
    assert_eq!(resolved.expires_at_ms["API_KEY"], 5000);
    assert_eq!(versions(&store, &provider).await.unwrap()["API_KEY"], 2);
    assert!(
        restarted
            .resolve_provider_handles(&provider, 5000)
            .await
            .unwrap()
            .expired_keys
            .contains("API_KEY")
    );
}

#[tokio::test]
async fn independent_runtimes_race_on_the_database_cas_and_clean_losing_candidates() {
    let store = Arc::new(crate::persistence::test_store().await);
    let config = Config::new(None);
    let first = CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap();
    let second = CredentialRuntime::from_config_with_store(&config, store.clone()).unwrap();
    let provider = write(&first).await;
    let scope = provider_scope(&provider, "API_KEY");
    let handle = &provider.credential_handles["API_KEY"];
    let (left, right) = tokio::join!(
        first.rotate_provider_reference(scope, handle, 1, "left", None),
        second.rotate_provider_reference(scope, handle, 1, "right", None),
    );
    assert_ne!(left.is_ok(), right.is_ok());
    let winner = if left.is_ok() { "left" } else { "right" };
    assert_eq!(
        left.err().or_else(|| right.err()).unwrap().code(),
        tonic::Code::Aborted
    );
    let resolved = first.resolve_provider_handles(&provider, 0).await.unwrap();
    assert_eq!(resolved.values["API_KEY"], winner);
    assert_eq!(resolved.versions["API_KEY"], 2);
    assert_eq!(
        store
            .list_by_type(DbCredstoreCredentialDriver::OBJECT_TYPE, 100, 0)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn stale_rotation_cannot_change_the_current_value() {
    let store = Arc::new(crate::persistence::test_store().await);
    let runtime = CredentialRuntime::from_config_with_store(&Config::new(None), store).unwrap();
    let provider = write(&runtime).await;
    let scope = provider_scope(&provider, "API_KEY");
    let handle = &provider.credential_handles["API_KEY"];
    runtime
        .rotate_provider_reference(scope, handle, 1, "second", None)
        .await
        .unwrap();
    assert_eq!(
        runtime
            .rotate_provider_reference(scope, handle, 1, "stale", None)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap()
            .values["API_KEY"],
        "second"
    );
}

#[tokio::test]
async fn legacy_migration_is_idempotent_and_does_not_rewrite_providers() {
    let store = Arc::new(crate::persistence::test_store().await);
    let runtime =
        CredentialRuntime::from_config_with_store(&Config::new(None), store.clone()).unwrap();
    // Write through the pre-issuer backend without creating a reference row.
    let handles = runtime
        .internal_secrets()
        .store(
            InternalSecretOwner {
                name: "provider",
                workspace: "workspace",
                id: "provider-id",
            },
            "legacy-candidate",
            &HashMap::from([("API_KEY".into(), "legacy-value".into())]),
        )
        .await
        .unwrap();
    let provider = provider(handles);
    store.put_message(&provider).await.unwrap();
    let before = store.get("provider", "provider-id").await.unwrap().unwrap();
    runtime.migrate_provider_references(&store).await.unwrap();
    runtime.migrate_provider_references(&store).await.unwrap();
    let after = store.get("provider", "provider-id").await.unwrap().unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.resource_version, after.resource_version);
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap()
            .versions["API_KEY"],
        1
    );
    let registry = runtime.references.as_ref().unwrap();
    assert_eq!(
        registry
            .observe(
                &reference_key(&provider.credential_handles["API_KEY"]).unwrap(),
                &owner(provider_scope(&provider, "API_KEY"))
            )
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
}

#[tokio::test]
async fn failed_backend_cleanup_keeps_revocation_durable_and_retryable() {
    let store = Arc::new(crate::persistence::test_store().await);
    let runtime = CredentialRuntime::from_config_with_store(
        &Config::new(None).with_credential_drivers(["test-static"]),
        store,
    )
    .unwrap();
    let provider = write(&runtime).await;
    runtime.fail_next_delete();
    assert_eq!(
        runtime
            .delete_provider_credential_handles(
                "provider",
                "workspace",
                "provider-id",
                &provider.credential_handles
            )
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Unavailable
    );
    assert_eq!(runtime.stored_credential_count(), Some(1));
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
    runtime
        .delete_provider_credential_handles(
            "provider",
            "workspace",
            "provider-id",
            &provider.credential_handles,
        )
        .await
        .unwrap();
    assert_eq!(runtime.stored_credential_count(), Some(0));
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}

#[tokio::test]
async fn rotation_cleanup_retries_without_changing_the_committed_version() {
    let store = Arc::new(crate::persistence::test_store().await);
    let runtime = CredentialRuntime::from_config_with_store(
        &Config::new(None).with_credential_drivers(["test-static"]),
        store,
    )
    .unwrap();
    let provider = write(&runtime).await;
    let handle = &provider.credential_handles["API_KEY"];
    runtime.fail_next_delete();
    runtime
        .rotate_provider_reference(
            provider_scope(&provider, "API_KEY"),
            handle,
            1,
            "second",
            None,
        )
        .await
        .unwrap();
    assert_eq!(runtime.stored_credential_count(), Some(2));
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap()
            .values["API_KEY"],
        "second"
    );
    runtime
        .rotate_provider_reference(
            provider_scope(&provider, "API_KEY"),
            handle,
            2,
            "third",
            None,
        )
        .await
        .unwrap();
    assert_eq!(runtime.stored_credential_count(), Some(1));
    assert_eq!(
        runtime
            .resolve_provider_handles(&provider, 0)
            .await
            .unwrap()
            .versions["API_KEY"],
        3
    );
}

#[tokio::test]
async fn another_provider_or_workspace_cannot_resolve_a_reference() {
    let store = Arc::new(crate::persistence::test_store().await);
    let runtime = CredentialRuntime::from_config_with_store(&Config::new(None), store).unwrap();
    let original = write(&runtime).await;
    for field in ["workspace", "id"] {
        let mut other = original.clone();
        let metadata = other.metadata.as_mut().unwrap();
        if field == "workspace" {
            metadata.workspace = "other".into();
        } else {
            metadata.id = "other".into();
        }
        assert_eq!(
            runtime
                .resolve_provider_handles(&other, 0)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}
