// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::persistence::Store;

mod fencing;
mod rotated_material;
use std::sync::Arc;

async fn put_established_grant(
    store: &Store,
    mut grant: crate::storage_proto::StoredProviderCredentialRefreshStateV2,
) {
    grant.status = "refreshed".to_string();
    grant.metadata.as_mut().unwrap().annotations.insert(
        crate::provider_refresh::COMPLETED_MINT_ANNOTATION.to_string(),
        "previous-success".to_string(),
    );
    put_refresh_state(store, &grant).await.unwrap();
}

async fn persisted_provider(keys: &[&str]) -> (Arc<Store>, CredentialRuntime, Provider) {
    let store = Arc::new(test_store().await);
    let credentials =
        CredentialRuntime::from_config_with_store(&Config::new(None), store.clone()).unwrap();
    let kind = if keys.contains(&"AWS_ACCESS_KEY_ID") {
        "aws"
    } else {
        "outlook"
    };
    let mut provider = provider("stable-refresh", kind);
    provider.credential_handles = credentials
        .store_provider_credentials(
            provider.object_name(),
            "default",
            provider.object_id(),
            &keys
                .iter()
                .map(|key| ((*key).to_string(), format!("old-{key}")))
                .collect(),
            &HashMap::new(),
        )
        .await
        .unwrap();
    for key in keys {
        provider.credential_expiration_times.insert(
            (*key).to_string(),
            openshell_core::time::timestamp_from_millis(1).unwrap(),
        );
    }
    store.put_message(&provider).await.unwrap();
    let provider = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    (store, credentials, provider)
}

#[tokio::test]
async fn persistent_oauth_refresh_keeps_provider_reference_and_revision_but_advances_value_and_expiry()
 {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-reference-value", "expires_in": 3600
        })))
        .expect(2)
        .mount(&mock)
        .await;
    let (store, credentials, provider) = persisted_provider(&["MS_GRAPH_ACCESS_TOKEN"]).await;
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
    put_established_grant(&store, grant).await;
    for version in 2..=3 {
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
        assert_eq!(refreshed.status, "refreshed");
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
        assert_eq!(resolved.versions["MS_GRAPH_ACCESS_TOKEN"], version);
        assert_eq!(
            resolved.values["MS_GRAPH_ACCESS_TOKEN"],
            "new-reference-value"
        );
        assert!(resolved.expires_at_ms["MS_GRAPH_ACCESS_TOKEN"] > current_time_ms());
        let mut projected = unchanged;
        crate::credentials::references::project_expiration_times(&store, &mut projected)
            .await
            .unwrap();
        assert_eq!(
            projected.credential_expiration_times["MS_GRAPH_ACCESS_TOKEN"],
            openshell_core::time::timestamp_from_millis(refreshed.expires_at_ms).unwrap()
        );
        assert_eq!(projected.metadata, provider.metadata);
    }
}

#[tokio::test]
async fn stable_aws_publication_updates_three_outputs_with_one_receipt_without_provider_mutation() {
    let mock = MockServer::start().await;
    Mock::given(method("POST")).and(body_string_contains("Action=AssumeRole"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>NEWKEY</AccessKeyId><SecretAccessKey>NEWSECRET</SecretAccessKey><SessionToken>NEWSESSION</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#, "text/xml"))
        .mount(&mock).await;
    let (store, credentials, provider) =
        persisted_provider(&["AWS_ACCESS_KEY_ID", "CUSTOM_SECRET", "CUSTOM_SESSION"]).await;
    let grant = new_refresh_state(
        &provider,
        "default",
        "AWS_ACCESS_KEY_ID",
        NewRefreshStateConfig {
            strategy: ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
            material: HashMap::from([
                (
                    "role_arn".to_string(),
                    "arn:aws:iam::123456789012:role/TestRole".to_string(),
                ),
                ("aws_access_key_id".to_string(), "SOURCEKEY".to_string()),
                (
                    "aws_secret_access_key".to_string(),
                    "SOURCESECRET".to_string(),
                ),
                ("sts_endpoint_url".to_string(), mock.uri()),
            ]),
            secret_material_keys: vec!["aws_secret_access_key".to_string()],
            token_url: String::new(),
            scopes: Vec::new(),
            additional_output_keys: HashMap::from([
                ("secret_access_key".to_string(), "CUSTOM_SECRET".to_string()),
                ("session_token".to_string(), "CUSTOM_SESSION".to_string()),
            ]),
            expires_at_ms: 0,
            refresh_before: None,
            max_lifetime: None,
        },
    )
    .unwrap();
    put_established_grant(&store, grant).await;
    let refreshed = refresh_provider_credential(
        &store,
        "default",
        &credentials,
        None,
        provider.object_name(),
        "AWS_ACCESS_KEY_ID",
    )
    .await
    .unwrap();
    assert_eq!(refreshed.status, "refreshed");
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
        resolved.values,
        HashMap::from([
            ("AWS_ACCESS_KEY_ID".to_string(), "NEWKEY".to_string()),
            ("CUSTOM_SECRET".to_string(), "NEWSECRET".to_string()),
            ("CUSTOM_SESSION".to_string(), "NEWSESSION".to_string()),
        ])
    );
    assert!(resolved.versions.values().all(|version| *version == 2));
    assert!(
        resolved
            .expires_at_ms
            .values()
            .all(|expiration| *expiration == refreshed.expires_at_ms)
    );
    let receipt = get_refresh_state(&store, "default", provider.object_id(), "AWS_ACCESS_KEY_ID")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        receipt.metadata.as_ref().unwrap().resource_version,
        refreshed.metadata.as_ref().unwrap().resource_version
    );
}
