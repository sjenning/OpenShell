// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::ProviderCredentialSource as _;
use openshell_core::{
    Config,
    proto::{ObjectMeta, Provider},
};
use std::collections::HashMap;

struct Fixture {
    directory: tempfile::TempDir,
    database: String,
    gateway: Arc<Store>,
    legacy: CredentialRuntime,
    crypto: toml::Table,
}
impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let database = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("gateway.db").display()
        );
        let gateway = Arc::new(Store::connect(&database).await.unwrap());
        let config = Config::new(None)
            .with_credential_drivers(["test-static"])
            .with_default_credential_driver(Some("test-static"));
        let legacy = CredentialRuntime::from_config_with_store(&config, gateway.clone()).unwrap();
        let crypto = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(
                directory
                    .path()
                    .join("issuer.key")
                    .to_string_lossy()
                    .into_owned(),
            ),
        )]);
        Self {
            directory,
            database,
            gateway,
            legacy,
            crypto,
        }
    }
    async fn host(&self) -> EmbeddedIssuer {
        EmbeddedIssuer::new(
            &self.database,
            &self.gateway,
            &self.legacy,
            &self.crypto,
            &BTreeMap::new(),
        )
        .await
        .unwrap()
    }
}
use std::collections::BTreeMap;
fn provider() -> Provider {
    Provider {
        metadata: Some(ObjectMeta {
            id: "provider".into(),
            name: "display".into(),
            workspace: "default".into(),
            ..Default::default()
        }),
        r#type: "custom".into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn embedded_upgrade_moves_inline_values_and_adopts_handles_without_reallocating_values() {
    let fixture = Fixture::new().await;
    let mut input = provider();
    input
        .credentials
        .insert("INLINE".into(), "inline-private".into());
    let long_key = "L".repeat(128);
    input
        .credentials
        .insert(long_key.clone(), "long-key-private".into());
    input.credential_handles = fixture
        .legacy
        .store_provider_credentials(
            "display",
            "default",
            "provider",
            &HashMap::from([("TOKEN".into(), "legacy-private".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    let original = input.credential_handles["TOKEN"].clone();
    let reference = crate::credentials::references::reference_key(&original).unwrap();
    fixture.gateway.put_message(&input).await.unwrap();
    let issuer = fixture.host().await;
    let upgraded = fixture
        .gateway
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    assert!(upgraded.credentials.is_empty());
    assert_eq!(
        issuer
            .source
            .decode(&upgraded.credential_handles["TOKEN"])
            .unwrap()
            .reference,
        reference
    );
    let values = issuer
        .source
        .resolve_provider_handles(&upgraded, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "legacy-private");
    assert_eq!(values.values["INLINE"], "inline-private");
    assert_eq!(values.values[&long_key], "long-key-private");
    let row = fixture
        .gateway
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&row.payload).contains("inline-private"));
    issuer.drain().await;
    drop(issuer);
    let restarted = fixture.host().await;
    let after = fixture
        .gateway
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.payload, after.payload);
    assert_eq!(row.resource_version, after.resource_version);
    let values = restarted
        .source
        .resolve_provider_handles(&upgraded, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "legacy-private");
    assert!(fixture.directory.path().join("issuer.key").exists());
}

#[tokio::test]
async fn internal_secrets_use_typed_owners_and_value_free_durable_intents() {
    use crate::credentials::InternalSecretOwner;
    use openshell_credential_issuer::SecretOwnerKind;
    let fixture = Fixture::new().await;
    let issuer = fixture.host().await;
    let owner = InternalSecretOwner {
        kind: SecretOwnerKind::Sandbox,
        name: "ignored-display",
        workspace: "default",
        id: "object",
    };
    let handles = issuer
        .source
        .store_internal(
            owner,
            "candidate",
            &HashMap::from([("KEY".into(), "internal-private".into())]),
        )
        .await
        .unwrap();
    issuer
        .source
        .issuer()
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let resolved = issuer
        .source
        .resolve_internal(owner, &handles)
        .await
        .unwrap();
    assert_eq!(resolved["KEY"], "internal-private");
    let other = InternalSecretOwner {
        kind: SecretOwnerKind::SupervisorInstance,
        ..owner
    };
    assert!(
        issuer
            .source
            .resolve_internal(other, &handles)
            .await
            .is_err()
    );
    let rows = fixture
        .gateway
        .list_object_page(
            "credential_issuer_internal_intent_v1",
            crate::persistence::ObjectListQuery::AllWorkspaces,
            None,
            100,
        )
        .await
        .unwrap();
    assert_eq!(rows.records.len(), 1);
    assert!(!String::from_utf8_lossy(&rows.records[0].payload).contains("internal-private"));
    issuer
        .source
        .delete_internal(owner, &handles)
        .await
        .unwrap();
    assert!(
        issuer
            .source
            .resolve_internal(owner, &handles)
            .await
            .is_err()
    );
    let config = Config::new(None);
    let runtime = CredentialRuntime::from_issuer(&config, issuer.source.clone()).unwrap();
    assert!(!runtime.stores_provider_credentials());
    assert_eq!(runtime.issuer_drivers().0.len(), 0);
}

#[tokio::test]
async fn legacy_refresh_adoption_publishes_then_activates_without_changing_epoch_or_provider_on_restart()
 {
    use crate::{provider_refresh, storage_proto::StoredProviderCredentialRefreshStateV2};
    use openshell_core::proto::ProviderCredentialRefreshStrategy as Strategy;
    let fixture = Fixture::new().await;
    let mut input = provider();
    input.credential_handles = fixture
        .legacy
        .store_provider_credentials(
            "display",
            "default",
            "provider",
            &HashMap::from([("TOKEN".into(), "existing-token".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    fixture.gateway.put_message(&input).await.unwrap();
    let now = crate::persistence::current_time_ms();
    let state = StoredProviderCredentialRefreshStateV2 {
        metadata: Some(ObjectMeta {
            id: "legacy-grant".into(),
            name: provider_refresh::refresh_state_name("provider", "TOKEN"),
            workspace: "default".into(),
            ..Default::default()
        }),
        provider_id: "provider".into(),
        provider_name: "display".into(),
        credential_key: "TOKEN".into(),
        strategy: Strategy::Oauth2RefreshToken as i32,
        authorization_epoch: "original-epoch".into(),
        status: "refreshed".into(),
        last_refresh_at_ms: now - 1000,
        expires_at_ms: now + 3_600_000,
        next_refresh_at_ms: now + 3_000_000,
        token_url: "https://idp.invalid/token".into(),
        material: HashMap::from([
            ("refresh_token".into(), "protected-refresh".into()),
            ("client_id".into(), "client".into()),
        ]),
        ..Default::default()
    };
    provider_refresh::put_refresh_state(&fixture.gateway, &state)
        .await
        .unwrap();
    let issuer = fixture.host().await;
    let upgraded = fixture
        .gateway
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    let binding = issuer
        .source
        .decode(&upgraded.credential_handles["TOKEN"])
        .unwrap();
    assert_eq!(binding.grant.as_deref(), Some("legacy-grant"));
    assert_eq!(
        binding.authorization_epoch.as_deref(),
        Some("original-epoch")
    );
    assert!(
        provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        issuer
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );
    let value = issuer
        .source
        .resolve_provider_handles(&upgraded, now)
        .await
        .unwrap();
    assert_eq!(value.values["TOKEN"], "existing-token");
    let before = fixture
        .gateway
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    issuer.drain().await;
    drop(issuer);
    let restarted = fixture.host().await;
    let after = fixture
        .gateway
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.resource_version, after.resource_version);
    assert!(
        restarted
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );
    let values = restarted
        .source
        .resolve_provider_handles(&upgraded, now)
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "existing-token");
}

#[tokio::test]
async fn startup_activation_recovery_requires_the_complete_published_gateway_bundle() {
    use crate::credential_source::{
        IssuerReferenceBinding,
        handoff::{GrantPlan, StaticHandoff},
    };
    use crate::persistence::AtomicWrite;
    use openshell_credential_issuer::{
        SecretOwner,
        grant::GrantIdentity,
        repository::grants::{GrantPhase, OutputBinding},
        service::{LegacyGrant, LegacyGrantOutput, LegacyGrantStatus},
    };
    use prost::Message as _;
    let fixture = Fixture::new().await;
    let issuer = fixture.host().await;
    let mut input = provider();
    let now = crate::persistence::current_time_ms();
    let owner = SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    };
    let wire_owner = super::super::wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    };
    let output = issuer
        .source
        .issuer()
        .put_secret(super::super::wire::PutSecretRequest {
            owner: Some(wire_owner),
            value: "original-token".into(),
            idempotency_key: "recovery-output".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let registry = openshell_credential_issuer::builtins::registry();
    let descriptor = registry
        .describe()
        .find(|value| value.name == "oauth2_refresh_token")
        .unwrap()
        .clone();
    let identity = GrantIdentity {
        id: "recovery-grant".into(),
        authorization_epoch: "exact-epoch".into(),
        owner,
    };
    issuer
        .refresh
        .import_legacy_grant(LegacyGrant {
            identity: identity.clone(),
            source_revision: 1,
            source_provider_version: 1,
            descriptor,
            outputs: BTreeMap::from([(
                "access_token".into(),
                LegacyGrantOutput {
                    binding: OutputBinding {
                        credential_key: "TOKEN".into(),
                        reference: output.reference.clone(),
                    },
                    version: output.version,
                },
            )]),
            config: BTreeMap::from([("token_url".into(), "https://idp.invalid/token".into())]),
            secret_material: BTreeMap::from([("refresh_token".into(), "refresh-private".into())]),
            refresh_before_ms: 1000,
            max_lifetime_seconds: 3600,
            status: LegacyGrantStatus {
                version: 1,
                phase: GrantPhase::Refreshed,
                expiration_time_ms: Some(now + 3_600_000),
                next_refresh_at_ms: now + 3_000_000,
                recovery_action: None,
                failure_code: String::new(),
                last_refresh_time_ms: Some(now),
                last_error_time_ms: None,
                provider_error_subtype: String::new(),
                attempt_id: None,
                completed_attempt: Some("prior-completion".into()),
                uncertain: false,
            },
            retired: Vec::new(),
        })
        .await
        .unwrap();
    // No gateway publication exists. A completed native import alone is not
    // authority to activate, even though the output reference already exists.
    let pending = issuer
        .refresh
        .pending_legacy_grants(None, 128)
        .await
        .unwrap();
    assert!(
        !StaticHandoff::legacy_activation_published(
            &fixture.gateway,
            &issuer.source,
            &pending.grants[0],
        )
        .await
        .unwrap()
    );
    assert_eq!(
        issuer
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .len(),
        1
    );
    let mut handle = issuer
        .source
        .reference_handle(&output.reference, Some(&identity.id))
        .unwrap();
    let mut binding: IssuerReferenceBinding = serde_json::from_str(&handle.handle).unwrap();
    binding.authorization_epoch = Some(identity.authorization_epoch.clone());
    handle.handle = serde_json::to_string(&binding).unwrap();
    input.credential_handles.insert("TOKEN".into(), handle);
    let journal = StaticHandoff::migration_write(
        &issuer.source,
        &input,
        &["TOKEN".into()],
        Some((
            GrantPlan {
                credential_key: "TOKEN".into(),
                strategy: "oauth2_refresh_token".into(),
                outputs: BTreeMap::from([("access_token".into(), "TOKEN".into())]),
                refresh_before_ms: 1000,
                max_lifetime_seconds: 3600,
            },
            identity.id.clone(),
        )),
    )
    .unwrap();
    fixture
        .gateway
        .write_atomically(&[
            journal,
            AtomicWrite::Create {
                object_type: "provider".into(),
                id: "provider".into(),
                name: "display".into(),
                workspace: "default".into(),
                payload: input.encode_to_vec(),
            },
        ])
        .await
        .unwrap();
    // Simulate loss of the postcommit activation acknowledgement by entering
    // the startup recovery path, with no legacy DTO left to trigger adoption.
    migration::providers(
        &fixture.gateway,
        &fixture.legacy,
        &issuer.store,
        &issuer.refresh,
        &issuer.source,
    )
    .await
    .unwrap();
    assert!(
        issuer
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );
    issuer.source.register_provider(&input).unwrap();
    issuer
        .source
        .issuer()
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let values = issuer
        .source
        .resolve_provider_handles(&input, now)
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "original-token");
    let before = fixture
        .gateway
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    migration::providers(
        &fixture.gateway,
        &fixture.legacy,
        &issuer.store,
        &issuer.refresh,
        &issuer.source,
    )
    .await
    .unwrap();
    assert_eq!(
        before.resource_version,
        fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap()
            .resource_version
    );
}

#[tokio::test]
async fn interrupted_legacy_refresh_deletion_finishes_cleanup_and_preserves_static_outputs() {
    use crate::{
        credentials::RefreshMaterialScope, provider_refresh,
        storage_proto::StoredProviderCredentialRefreshStateV2,
    };
    use openshell_core::proto::ProviderCredentialRefreshStrategy as Strategy;
    let fixture = Fixture::new().await;
    let issuer = fixture.host().await;
    for worker in &issuer.workers {
        worker.abort();
    }
    let mut input = provider();
    input
        .credentials
        .insert("TOKEN".into(), "preserved-output".into());
    fixture.gateway.put_message(&input).await.unwrap();
    // This copy predates an old replica's reconfiguration AND deletion. The
    // tombstone epoch below differs, so cleanup must retrieve the original
    // dormant identity rather than guessing it from the current DTO.
    let (dormant_identity, original_reference) =
        dormant_import(&issuer, "deleting-grant", "before-reconfiguration").await;
    let scope = RefreshMaterialScope {
        provider_name: "display",
        workspace: "default",
        provider_id: "provider",
        credential_key: "TOKEN",
    };
    let handles = fixture
        .legacy
        .store_refresh_material_with_object_id(
            scope,
            "deleted-material",
            &HashMap::from([("refresh_token".into(), "deleted-private-material".into())]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    // The old delete path committed a tombstone, removed backend material, and
    // crashed before deleting its DTO. Startup must never try resolving it.
    let state = StoredProviderCredentialRefreshStateV2 {
        metadata: Some(ObjectMeta {
            id: "deleting-grant".into(),
            name: provider_refresh::refresh_state_name("provider", "TOKEN"),
            workspace: "default".into(),
            deletion_time: Some(
                openshell_core::time::timestamp_from_millis(crate::persistence::current_time_ms())
                    .unwrap(),
            ),
            ..Default::default()
        }),
        provider_id: "provider".into(),
        provider_name: "display".into(),
        credential_key: "TOKEN".into(),
        strategy: Strategy::Oauth2RefreshToken as i32,
        authorization_epoch: "deletion-tombstone-epoch".into(),
        status: "deleting".into(),
        secret_material_handles: handles.clone(),
        next_refresh_at_ms: i64::MAX,
        ..Default::default()
    };
    provider_refresh::put_refresh_state(&fixture.gateway, &state)
        .await
        .unwrap();
    fixture
        .legacy
        .delete_refresh_material_handles(scope, &handles)
        .await
        .unwrap();
    assert!(
        fixture
            .legacy
            .resolve_refresh_material(scope, &handles)
            .await
            .is_err()
    );
    migration::providers(
        &fixture.gateway,
        &fixture.legacy,
        &issuer.store,
        &issuer.refresh,
        &issuer.source,
    )
    .await
    .unwrap();
    let upgraded = fixture
        .gateway
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    assert!(
        provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        issuer
            .source
            .decode(&upgraded.credential_handles["TOKEN"])
            .unwrap()
            .grant
            .is_none()
    );
    assert!(
        issuer
            .source
            .refresh_authorization_epochs(&upgraded)
            .unwrap()
            .is_empty()
    );
    issuer.source.register_provider(&upgraded).unwrap();
    issuer
        .source
        .issuer()
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let values = issuer
        .source
        .resolve_provider_handles(&upgraded, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "preserved-output");
    assert_native_copies_retired(&fixture, &issuer).await;
    let original = issuer
        .store
        .legacy_reference_state(&original_reference, &dormant_identity.owner)
        .await
        .unwrap();
    assert_eq!(original.version, 1);
    assert!(!original.revoked);
    assert_eq!(
        issuer
            .refresh
            .activate_legacy_grant(dormant_identity)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition,
    );
    assert!(
        issuer
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );
}

/// Model a prior startup that durably prepared native copies but did not commit
/// the gateway publication transaction. The output value is never a copy owned
/// by the dormant import and must survive its abandonment.
async fn dormant_import(
    issuer: &EmbeddedIssuer,
    id: &str,
    epoch: &str,
) -> (openshell_credential_issuer::grant::GrantIdentity, String) {
    use openshell_credential_issuer::{
        SecretOwner,
        grant::GrantIdentity,
        repository::grants::{GrantPhase, OutputBinding},
        service::{LegacyGrant, LegacyGrantOutput, LegacyGrantStatus},
    };
    let owner = SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    };
    let output = issuer
        .source
        .issuer()
        .put_secret(super::super::wire::PutSecretRequest {
            owner: Some(super::super::wire::SecretOwner {
                workspace: owner.workspace.clone(),
                provider_id: owner.provider_id.clone(),
                credential_key: owner.credential_key.clone(),
                ..Default::default()
            }),
            value: "preserved-output".into(),
            idempotency_key: format!("dormant-output-{id}"),
            ..Default::default()
        })
        .await
        .unwrap();
    let identity = GrantIdentity {
        id: id.into(),
        authorization_epoch: epoch.into(),
        owner,
    };
    let descriptor = openshell_credential_issuer::builtins::registry()
        .describe()
        .find(|descriptor| descriptor.name == "oauth2_refresh_token")
        .unwrap()
        .clone();
    issuer
        .refresh
        .import_legacy_grant(LegacyGrant {
            identity: identity.clone(),
            source_revision: 1,
            source_provider_version: 1,
            descriptor,
            outputs: BTreeMap::from([(
                "access_token".into(),
                LegacyGrantOutput {
                    binding: OutputBinding {
                        credential_key: "TOKEN".into(),
                        reference: output.reference.clone(),
                    },
                    version: output.version,
                },
            )]),
            config: BTreeMap::from([("token_url".into(), "https://idp.invalid/token".into())]),
            secret_material: BTreeMap::from([(
                "refresh_token".into(),
                "dormant-private-copy".into(),
            )]),
            refresh_before_ms: 1000,
            max_lifetime_seconds: 3600,
            status: LegacyGrantStatus {
                version: 1,
                phase: GrantPhase::Pending,
                expiration_time_ms: None,
                next_refresh_at_ms: i64::MAX,
                recovery_action: None,
                failure_code: String::new(),
                last_refresh_time_ms: None,
                last_error_time_ms: None,
                provider_error_subtype: String::new(),
                attempt_id: None,
                completed_attempt: None,
                uncertain: false,
            },
            retired: Vec::new(),
        })
        .await
        .unwrap();
    (identity, output.reference)
}

async fn assert_native_copies_retired(fixture: &Fixture, issuer: &EmbeddedIssuer) {
    let repository = Repository::open(&fixture.database).await.unwrap();
    let scope = issuer.store.embedded_scope().unwrap();
    let store = repository.for_gateway(&scope);
    assert_eq!(
        store
            .list("secret-candidate-v1", None, 128)
            .await
            .unwrap()
            .len(),
        2,
        "both native configuration and material copies must regain cleanup ownership"
    );
    assert_eq!(
        store
            .list("embedded-grant-import-abandoned-v1", None, 128)
            .await
            .unwrap()
            .len(),
        1
    );
    let worker = issuer
        .store
        .spawn_maintenance(Duration::from_millis(10))
        .unwrap();
    let cleaned = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if store
                .list("secret-candidate-v1", None, 128)
                .await
                .unwrap()
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    worker.abort();
    cleaned.unwrap();
}

#[tokio::test]
async fn completed_dormant_import_without_legacy_dto_is_abandoned_even_without_its_provider() {
    for provider_present in [false, true] {
        let fixture = Fixture::new().await;
        let issuer = fixture.host().await;
        for worker in &issuer.workers {
            worker.abort();
        }
        if provider_present {
            fixture.gateway.put_message(&provider()).await.unwrap();
        }
        let (identity, reference) =
            dormant_import(&issuer, "orphaned-grant", "original-epoch").await;
        migration::providers(
            &fixture.gateway,
            &fixture.legacy,
            &issuer.store,
            &issuer.refresh,
            &issuer.source,
        )
        .await
        .unwrap();
        assert!(
            issuer
                .refresh
                .pending_legacy_grants(None, 128)
                .await
                .unwrap()
                .grants
                .is_empty()
        );
        assert_native_copies_retired(&fixture, &issuer).await;
        let observed = issuer
            .store
            .legacy_reference_state(&reference, &identity.owner)
            .await
            .unwrap();
        assert_eq!(observed.version, 1);
        assert!(!observed.revoked);
        assert_eq!(
            issuer
                .refresh
                .activate_legacy_grant(identity)
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
    }
}

#[tokio::test]
async fn nonmintable_legacy_strategies_finish_all_material_cleanup_and_preserve_static_outputs() {
    use crate::{
        credentials::RefreshMaterialScope,
        provider_refresh,
        storage_proto::{StoredProviderCredentialRefreshStateV2, StoredRefreshMaterialDeletion},
    };
    use openshell_core::proto::ProviderCredentialRefreshStrategy as Strategy;
    for strategy in [Strategy::Static, Strategy::External, Strategy::Unspecified] {
        let fixture = Fixture::new().await;
        let mut input = provider();
        input.credential_handles = fixture
            .legacy
            .store_provider_credentials(
                "display",
                "default",
                "provider",
                &HashMap::from([("TOKEN".into(), "exact-static-output".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        let original_reference =
            crate::credentials::references::reference_key(&input.credential_handles["TOKEN"])
                .unwrap();
        fixture.gateway.put_message(&input).await.unwrap();
        let scope = RefreshMaterialScope {
            provider_name: "display",
            workspace: "default",
            provider_id: "provider",
            credential_key: "TOKEN",
        };
        let active = fixture
            .legacy
            .store_refresh_material_with_object_id(
                scope,
                "nonmintable-active-material",
                &HashMap::from([("refresh_token".into(), "active-private-material".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        let retired = fixture
            .legacy
            .store_refresh_material_with_object_id(
                scope,
                "nonmintable-retired-material",
                &HashMap::from([("refresh_token".into(), "retired-private-material".into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            fixture
                .legacy
                .resolve_refresh_material(scope, &active)
                .await
                .unwrap()["refresh_token"],
            "active-private-material"
        );
        assert_eq!(
            fixture
                .legacy
                .resolve_refresh_material(scope, &retired)
                .await
                .unwrap()["refresh_token"],
            "retired-private-material"
        );
        let state = StoredProviderCredentialRefreshStateV2 {
            metadata: Some(ObjectMeta {
                id: "nonmintable-grant".into(),
                name: provider_refresh::refresh_state_name("provider", "TOKEN"),
                workspace: "default".into(),
                ..Default::default()
            }),
            provider_id: "provider".into(),
            provider_name: "display".into(),
            credential_key: "TOKEN".into(),
            strategy: strategy as i32,
            authorization_epoch: "nonmintable-epoch".into(),
            status: "configured".into(),
            secret_material_handles: active.clone(),
            pending_secret_deletions: vec![StoredRefreshMaterialDeletion {
                material_key: "refresh_token".into(),
                handle: Some(retired["refresh_token"].clone()),
            }],
            ..Default::default()
        };
        provider_refresh::put_refresh_state(&fixture.gateway, &state)
            .await
            .unwrap();
        let issuer = fixture.host().await;
        let upgraded = fixture
            .gateway
            .get_message::<Provider>("provider")
            .await
            .unwrap()
            .unwrap();
        assert!(
            provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .legacy
                .resolve_refresh_material(scope, &active)
                .await
                .is_err()
        );
        assert!(
            fixture
                .legacy
                .resolve_refresh_material(scope, &retired)
                .await
                .is_err()
        );
        let binding = issuer
            .source
            .decode(&upgraded.credential_handles["TOKEN"])
            .unwrap();
        assert_eq!(binding.reference, original_reference);
        assert!(binding.grant.is_none());
        assert!(binding.authorization_epoch.is_none());
        assert!(
            issuer
                .source
                .refresh_authorization_epochs(&upgraded)
                .unwrap()
                .is_empty()
        );
        let values = issuer
            .source
            .resolve_provider_handles(&upgraded, crate::persistence::current_time_ms())
            .await
            .unwrap();
        assert_eq!(values.values["TOKEN"], "exact-static-output");
        assert!(
            issuer
                .refresh
                .pending_legacy_grants(None, 128)
                .await
                .unwrap()
                .grants
                .is_empty()
        );
    }
}

#[tokio::test]
async fn unknown_legacy_strategy_fails_closed_before_cleanup_or_publication() {
    use crate::{provider_refresh, storage_proto::StoredProviderCredentialRefreshStateV2};
    let fixture = Fixture::new().await;
    let mut input = provider();
    input
        .credentials
        .insert("TOKEN".into(), "untouched-output".into());
    fixture.gateway.put_message(&input).await.unwrap();
    let state = StoredProviderCredentialRefreshStateV2 {
        metadata: Some(ObjectMeta {
            id: "unknown-strategy-grant".into(),
            name: provider_refresh::refresh_state_name("provider", "TOKEN"),
            workspace: "default".into(),
            ..Default::default()
        }),
        provider_id: "provider".into(),
        provider_name: "display".into(),
        credential_key: "TOKEN".into(),
        strategy: i32::MAX,
        status: "configured".into(),
        ..Default::default()
    };
    provider_refresh::put_refresh_state(&fixture.gateway, &state)
        .await
        .unwrap();
    let error = EmbeddedIssuer::new(
        &fixture.database,
        &fixture.gateway,
        &fixture.legacy,
        &fixture.crypto,
        &BTreeMap::new(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    let retained = provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
        .await
        .unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].strategy, i32::MAX);
    assert!(
        retained[0]
            .metadata
            .as_ref()
            .unwrap()
            .deletion_time
            .is_none()
    );
    let retained = fixture
        .gateway
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.credentials["TOKEN"], "untouched-output");
    assert!(retained.credential_handles.is_empty());
}
