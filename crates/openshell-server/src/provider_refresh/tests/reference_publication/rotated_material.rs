// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn stable_reference_publication_preserves_each_rotated_refresh_token_for_the_next_exchange() {
    let mock = MockServer::start().await;
    for (input, output) in [
        ("initial-grant", "rotated-one"),
        ("rotated-one", "rotated-two"),
    ] {
        Mock::given(method("POST")).and(path("/token"))
            .and(body_string_contains(format!("refresh_token={input}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": format!("access-{output}"), "refresh_token": output, "expires_in": 3600,
            }))).expect(1).mount(&mock).await;
    }
    let (store, credentials, provider) = persisted_provider(&["MS_GRAPH_ACCESS_TOKEN"]).await;
    let grant = new_refresh_state(
        &provider,
        "default",
        "MS_GRAPH_ACCESS_TOKEN",
        NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            material: HashMap::from([
                ("client_id".to_string(), "client".to_string()),
                ("refresh_token".to_string(), "initial-grant".to_string()),
            ]),
            secret_material_keys: vec!["refresh_token".to_string()],
            token_url: format!("{}/token", mock.uri()),
            scopes: Vec::new(),
            additional_output_keys: HashMap::new(),
            expires_at_ms: 0,
            refresh_before: None,
            max_lifetime: None,
        },
    )
    .unwrap();
    put_established_grant(&store, grant).await;
    for (version, token) in [(2, "rotated-one"), (3, "rotated-two")] {
        let refreshed = refresh_provider_credential(
            &store,
            "default",
            &credentials,
            None,
            provider.object_name(),
            "MS_GRAPH_ACCESS_TOKEN",
        )
        .await
        .unwrap();
        assert!(!refreshed.material.contains_key("refresh_token"));
        assert!(refreshed.pending_secret_deletions.is_empty());
        let resolved_material = credentials
            .resolve_refresh_material(
                refresh_material_scope(&refreshed),
                &refreshed.secret_material_handles,
            )
            .await
            .unwrap();
        assert_eq!(resolved_material["refresh_token"], token);
        let unchanged = store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged, provider);
        let resolved = credentials
            .resolve_provider_handles(&unchanged, current_time_ms())
            .await
            .unwrap();
        assert_eq!(
            resolved.values["MS_GRAPH_ACCESS_TOKEN"],
            format!("access-{token}")
        );
        assert_eq!(resolved.versions["MS_GRAPH_ACCESS_TOKEN"], version);
    }
}

#[tokio::test]
async fn first_mint_establishes_references_then_later_mints_keep_the_provider_record_unchanged() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "minted", "expires_in": 3600,
        })))
        .expect(3)
        .mount(&mock)
        .await;
    let (store, credentials, provider) = persisted_provider(&[]).await;
    let grant = new_refresh_state(
        &provider,
        "default",
        "MS_GRAPH_ACCESS_TOKEN",
        NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            material: HashMap::from([
                ("client_id".to_string(), "client".to_string()),
                ("client_secret".to_string(), "secret".to_string()),
            ]),
            secret_material_keys: vec!["client_secret".to_string()],
            token_url: format!("{}/token", mock.uri()),
            scopes: Vec::new(),
            additional_output_keys: HashMap::new(),
            expires_at_ms: 0,
            refresh_before: None,
            max_lifetime: None,
        },
    )
    .unwrap();
    put_refresh_state(&store, &grant).await.unwrap();
    refresh_provider_credential(
        &store,
        "default",
        &credentials,
        None,
        provider.object_name(),
        "MS_GRAPH_ACCESS_TOKEN",
    )
    .await
    .unwrap();
    let established = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(
        established
            .credential_handles
            .contains_key("MS_GRAPH_ACCESS_TOKEN")
    );
    assert_eq!(
        credentials
            .resolve_provider_handles(&established, current_time_ms())
            .await
            .unwrap()
            .versions["MS_GRAPH_ACCESS_TOKEN"],
        1
    );
    refresh_provider_credential(
        &store,
        "default",
        &credentials,
        None,
        provider.object_name(),
        "MS_GRAPH_ACCESS_TOKEN",
    )
    .await
    .unwrap();
    let rotated = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rotated, established);
    assert_eq!(
        credentials
            .resolve_provider_handles(&rotated, current_time_ms())
            .await
            .unwrap()
            .versions["MS_GRAPH_ACCESS_TOKEN"],
        2
    );
    // A new authorization epoch must establish new references, never rotate the
    // preceding epoch's now-retained reference identity.
    let mut reconfigured = get_refresh_state(
        &store,
        "default",
        provider.object_id(),
        "MS_GRAPH_ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    reconfigured.authorization_epoch = uuid::Uuid::new_v4().to_string();
    reconfigured.status = "configured".to_string();
    crate::provider_refresh::reset_mint_receipts(&mut reconfigured);
    put_refresh_state(&store, &reconfigured).await.unwrap();
    refresh_provider_credential(
        &store,
        "default",
        &credentials,
        None,
        provider.object_name(),
        "MS_GRAPH_ACCESS_TOKEN",
    )
    .await
    .unwrap();
    let fresh_epoch = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(fresh_epoch.credential_handles, rotated.credential_handles);
    assert_eq!(
        credentials
            .resolve_provider_handles(&fresh_epoch, current_time_ms())
            .await
            .unwrap()
            .versions["MS_GRAPH_ACCESS_TOKEN"],
        1
    );
    assert_eq!(
        credentials
            .resolve_provider_handles(&rotated, current_time_ms())
            .await
            .unwrap_err()
            .code(),
        tonic::Code::NotFound
    );
}
