// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn stale_publication_changes_no_sibling_outputs(change_reference: bool) {
    let mock = MockServer::start().await;
    let (hit_tx, hit_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    Mock::given(method("POST")).and(body_string_contains("Action=AssumeRole"))
        .respond_with(GatedStsResponder {
            hit: std::sync::Mutex::new(Some(hit_tx)), release: std::sync::Mutex::new(release_rx),
            body: r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>LOSINGKEY</AccessKeyId><SecretAccessKey>LOSINGSECRET</SecretAccessKey><SessionToken>LOSINGSESSION</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#.to_string(),
        }).mount(&mock).await;
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
            expires_at_ms: 0,
            refresh_before: None,
            max_lifetime: None,
            additional_output_keys: HashMap::from([
                ("secret_access_key".to_string(), "CUSTOM_SECRET".to_string()),
                ("session_token".to_string(), "CUSTOM_SESSION".to_string()),
            ]),
        },
    )
    .unwrap();
    put_established_grant(&store, grant).await;
    let rotate = refresh_provider_credential(
        &store,
        "default",
        &credentials,
        None,
        provider.object_name(),
        "AWS_ACCESS_KEY_ID",
    );
    let interfere = async {
        tokio::time::timeout(std::time::Duration::from_secs(15), hit_rx)
            .await
            .unwrap()
            .unwrap();
        if change_reference {
            credentials
                .rotate_provider_reference(
                    crate::credentials::references::provider_scope(&provider, "AWS_ACCESS_KEY_ID"),
                    &provider.credential_handles["AWS_ACCESS_KEY_ID"],
                    1,
                    "external-winner",
                    None,
                )
                .await
                .unwrap();
        } else {
            store
                .update_message_cas::<Provider, _>(provider.object_id(), 0, |replacement| {
                    replacement
                        .config
                        .insert("changed".to_string(), "true".to_string());
                })
                .await
                .unwrap();
        }
        release_tx.send(()).unwrap();
    };
    let (result, ()) = tokio::join!(rotate, interfere);
    assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);
    let current = store
        .get_message::<Provider>(provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.credential_handles, provider.credential_handles);
    let resolved = credentials
        .resolve_provider_handles(&current, 0)
        .await
        .unwrap();
    assert_eq!(resolved.values["CUSTOM_SECRET"], "old-CUSTOM_SECRET");
    assert_eq!(resolved.values["CUSTOM_SESSION"], "old-CUSTOM_SESSION");
    assert_eq!(resolved.versions["CUSTOM_SECRET"], 1);
    assert_eq!(resolved.versions["CUSTOM_SESSION"], 1);
    assert_eq!(
        resolved.values["AWS_ACCESS_KEY_ID"],
        if change_reference {
            "external-winner"
        } else {
            "old-AWS_ACCESS_KEY_ID"
        }
    );
    assert_eq!(
        resolved.versions["AWS_ACCESS_KEY_ID"],
        if change_reference { 2 } else { 1 }
    );
    let receipt = get_refresh_state(&store, "default", provider.object_id(), "AWS_ACCESS_KEY_ID")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, "error");
    assert_ne!(
        receipt
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(crate::provider_refresh::COMPLETED_MINT_ANNOTATION),
        receipt
            .metadata
            .as_ref()
            .unwrap()
            .annotations
            .get(crate::provider_refresh::ATTEMPT_ANNOTATION)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn provider_version_change_during_mint_fences_all_reference_outputs() {
    stale_publication_changes_no_sibling_outputs(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reference_value_change_during_mint_fences_all_sibling_outputs() {
    stale_publication_changes_no_sibling_outputs(true).await;
}
