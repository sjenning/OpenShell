// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    credential_source::handoff::{GrantPlan, StaticHandoff},
    credentials::RefreshMaterialScope,
    provider_refresh,
    storage_proto::StoredProviderCredentialRefreshStateV2,
};
use openshell_core::proto::ProviderCredentialRefreshStrategy as Strategy;

async fn seed_refresh(fixture: &Fixture, key: &str) -> StoredProviderCredentialRefreshStateV2 {
    let mut input = provider();
    input
        .credentials
        .insert(key.into(), "existing-token".into());
    fixture.gateway.put_message(&input).await.unwrap();
    let now = crate::persistence::current_time_ms();
    StoredProviderCredentialRefreshStateV2 {
        metadata: Some(ObjectMeta {
            id: "legacy-contract-grant".into(),
            name: provider_refresh::refresh_state_name("provider", key),
            workspace: "default".into(),
            ..Default::default()
        }),
        provider_id: "provider".into(),
        provider_name: "display".into(),
        credential_key: key.into(),
        strategy: Strategy::Oauth2RefreshToken as i32,
        authorization_epoch: "original-epoch".into(),
        status: "refreshed".into(),
        last_refresh_at_ms: now - 1000,
        expires_at_ms: now + 3_600_000,
        next_refresh_at_ms: now + 3_000_000,
        token_url: "https://profile-authority.invalid/token".into(),
        material: HashMap::from([
            ("client_id".into(), "legacy-client".into()),
            ("refresh_token".into(), "private-refresh".into()),
        ]),
        ..Default::default()
    }
}

async fn endpoint_alias(
    fixture: &Fixture,
    state: &mut StoredProviderCredentialRefreshStateV2,
    alias: &str,
    protected: bool,
) {
    if protected {
        state.secret_material_keys.push("token_uri".into());
        state.secret_material_handles = fixture
            .legacy
            .store_refresh_material_with_object_id(
                RefreshMaterialScope {
                    provider_name: "display",
                    workspace: "default",
                    provider_id: "provider",
                    credential_key: &state.credential_key,
                },
                "legacy-endpoint-alias",
                &HashMap::from([("token_uri".into(), alias.into())]),
                &HashMap::new(),
            )
            .await
            .unwrap();
    } else {
        state.material.insert("token_uri".into(), alias.into());
    }
}

async fn assert_published(fixture: &Fixture, issuer: &EmbeddedIssuer, key: &str) -> Provider {
    let upgraded = fixture
        .gateway
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    assert!(upgraded.credentials.is_empty());
    let binding = issuer
        .source
        .decode(&upgraded.credential_handles[key])
        .unwrap();
    assert_eq!(binding.grant.as_deref(), Some("legacy-contract-grant"));
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
    assert_migrated_schedule(fixture, issuer, "legacy-contract-grant", 300_000, 3600).await;
    let values = issuer
        .source
        .resolve_provider_handles(&upgraded, crate::persistence::current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values[key], "existing-token");
    upgraded
}

#[tokio::test]
async fn legacy_refresh_migration_preserves_129_and_256_byte_environment_keys_on_restart() {
    for length in [129, 256] {
        let fixture = Fixture::new().await;
        let key = "K".repeat(length);
        let state = seed_refresh(&fixture, &key).await;
        provider_refresh::put_refresh_state(&fixture.gateway, &state)
            .await
            .unwrap();
        let issuer = fixture.host().await;
        let upgraded = assert_published(&fixture, &issuer, &key).await;
        let before = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap();
        issuer.drain().await;
        drop(issuer);
        let restarted = fixture.host().await;
        assert_eq!(assert_published(&fixture, &restarted, &key).await, upgraded);
        let after = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.payload, after.payload);
        assert_eq!(before.resource_version, after.resource_version);
    }
}

#[tokio::test]
async fn native_refresh_reservations_share_the_256_byte_key_bound() {
    let fixture = Fixture::new().await;
    let issuer = fixture.host().await;
    for length in [129, 256] {
        let key = "K".repeat(length);
        let mut handoff = StaticHandoff::begin_grant(
            &fixture.gateway,
            &issuer.source,
            &provider(),
            GrantPlan {
                credential_key: key.clone(),
                strategy: "oauth2_refresh_token".into(),
                outputs: BTreeMap::from([("access_token".into(), key)]),
                refresh_before_ms: 300_000,
                max_lifetime_seconds: 3600,
            },
            None,
        )
        .await
        .unwrap();
        handoff
            .reserve(&fixture.gateway, &issuer.source)
            .await
            .unwrap();
        handoff
            .abort(&fixture.gateway, &issuer.source)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn legacy_refresh_migration_rejects_overlong_and_invalid_environment_keys() {
    for key in ["K".repeat(257), "1TOKEN".into(), "TOKEN-NAME".into()] {
        let fixture = Fixture::new().await;
        let state = seed_refresh(&fixture, &key).await;
        provider_refresh::put_refresh_state(&fixture.gateway, &state)
            .await
            .unwrap();
        let before = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap();
        assert!(
            EmbeddedIssuer::new(
                &fixture.database,
                &fixture.gateway,
                &fixture.legacy,
                &fixture.crypto,
                &BTreeMap::new(),
            )
            .await
            .is_err()
        );
        let after = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.payload, after.payload);
        assert_eq!(before.resource_version, after.resource_version);
        assert_eq!(
            provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
                .await
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn legacy_refresh_migration_normalizes_only_blank_token_uri_including_protected_material() {
    for protected in [false, true] {
        for alias in ["", " \t\r\n"] {
            let fixture = Fixture::new().await;
            let mut state = seed_refresh(&fixture, "TOKEN").await;
            endpoint_alias(&fixture, &mut state, alias, protected).await;
            provider_refresh::put_refresh_state(&fixture.gateway, &state)
                .await
                .unwrap();
            let issuer = fixture.host().await;
            assert_published(&fixture, &issuer, "TOKEN").await;
            // Read the actual encrypted imported configuration, not just the
            // DTO projection: the profile's typed endpoint must be preserved.
            let scope = issuer.store.embedded_scope().unwrap();
            let imported = fixture
                .repository
                .grants(&scope)
                .load("legacy-contract-grant")
                .await
                .unwrap()
                .unwrap()
                .state;
            let (drivers, default) = fixture.legacy.issuer_drivers();
            let storage = CredentialStorage::new(drivers, default).unwrap();
            let config = storage
                .resolve(
                    &scope,
                    &imported.definition.identity.owner,
                    "grant-config-v1:legacy-contract-grant:original-epoch",
                    &imported.definition.config_backing,
                )
                .await
                .unwrap();
            let config: BTreeMap<String, String> = serde_json::from_str(&config.value).unwrap();
            assert_eq!(config["token_url"], state.token_url);
            assert!(!config.contains_key("token_uri"));
            assert!(!imported.material.contains_key("token_uri"));
        }
    }
}

#[tokio::test]
async fn legacy_refresh_migration_rejects_nonempty_token_uri_without_publication() {
    for protected in [false, true] {
        let fixture = Fixture::new().await;
        let mut state = seed_refresh(&fixture, "TOKEN").await;
        endpoint_alias(
            &fixture,
            &mut state,
            " https://attacker.invalid/token ",
            protected,
        )
        .await;
        provider_refresh::put_refresh_state(&fixture.gateway, &state)
            .await
            .unwrap();
        let before = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
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
        let after = fixture
            .gateway
            .get("provider", "provider")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.payload, after.payload);
        assert_eq!(before.resource_version, after.resource_version);
        let retained =
            provider_refresh::list_refresh_states_for_provider(&fixture.gateway, "provider")
                .await
                .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].token_url, state.token_url);
        assert_eq!(
            retained[0].secret_material_handles,
            state.secret_material_handles
        );
        assert_eq!(retained[0].material, state.material);
        let rows = fixture
            .gateway
            .list_object_page(
                "credential_issuer_handoff_v1",
                crate::persistence::ObjectListQuery::AllWorkspaces,
                None,
                128,
            )
            .await
            .unwrap();
        assert!(rows.records.is_empty());
    }
}
