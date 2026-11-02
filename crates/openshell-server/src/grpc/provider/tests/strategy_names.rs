// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::ObjectMeta;

#[tokio::test]
async fn configure_names_are_canonicalized_before_durable_grant_creation() {
    let state = test_server_state().await;
    import_test_graph_refresh_profile(&state).await;
    let provider = create_provider_record(
        state.store.as_ref(),
        "default",
        Provider {
            metadata: Some(ObjectMeta {
                name: "named-strategy".to_string(),
                ..Default::default()
            }),
            r#type: TEST_GRAPH_PROVIDER_TYPE.to_string(),
            profile_workspace: "default".to_string(),
            credentials: HashMap::from([(
                "MS_GRAPH_ACCESS_TOKEN".to_string(),
                "initial".to_string(),
            )]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let builtin = ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32;
    let name = "oauth2_client_credentials";
    let request = |strategy, strategy_name: &str| ConfigureProviderRefreshRequest {
        workspace_scope: Some(openshell_core::proto::workspace_selector(
            "default".to_string(),
        )),
        provider: "named-strategy".to_string(),
        credential_key: "MS_GRAPH_ACCESS_TOKEN".to_string(),
        strategy,
        strategy_name: strategy_name.to_string(),
        material: HashMap::from([
            ("client_id".to_string(), "client".to_string()),
            ("tenant_id".to_string(), "tenant".to_string()),
            ("client_secret".to_string(), "secret".to_string()),
        ]),
        ..Default::default()
    };
    for (strategy, strategy_name) in [(0, name), (builtin, name), (builtin, "")] {
        let result = handle_configure_provider_refresh(
            &state,
            authed_request(request(strategy, strategy_name)),
        )
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
        assert_eq!(result.strategy, builtin);
        assert_eq!(result.strategy_name, name);
    }
    let before = crate::provider_refresh::get_refresh_state(
        &state.store,
        "default",
        provider.object_id(),
        "MS_GRAPH_ACCESS_TOKEN",
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(before.strategy, builtin);
    assert!(before.secret_material_handles.contains_key("client_secret"));
    assert!(!before.material.contains_key("client_secret"));
    for (strategy, strategy_name) in [
        (1, name),
        (i32::MAX, name),
        (builtin, "custom:acme"),
        (0, "custom:acme"),
    ] {
        let error = handle_configure_provider_refresh(
            &state,
            authed_request(request(strategy, strategy_name)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!(
            crate::provider_refresh::get_refresh_state(
                &state.store,
                "default",
                provider.object_id(),
                "MS_GRAPH_ACCESS_TOKEN"
            )
            .await
            .unwrap()
            .unwrap(),
            before
        );
    }
}
