// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Exercise public provider creation/export against the real issuer handlers in
//! both transports, without sharing the embedded migration test module.

use super::*;
use crate::{
    ServerState,
    auth::{
        identity::{Identity, IdentityProvider},
        principal::{OperatorPrincipal, Principal},
    },
    credential_source::embedded::EmbeddedIssuer,
    grpc::{
        OpenShellService,
        test_support::{authed_request, test_server_state},
    },
};
use openshell_core::{
    ObjectId as _,
    proto::{
        CreateProviderRequest, GetProviderCredentialsRequest, ProviderProfile,
        ProviderProfileCredential, open_shell_server::OpenShell as _, workspace_selector,
    },
};
use std::{collections::BTreeMap, sync::Arc};
use tonic::{Code, Request};

fn export_request(keys: Vec<String>) -> Request<GetProviderCredentialsRequest> {
    let mut request = Request::new(GetProviderCredentialsRequest {
        name: "long-key-provider".into(),
        workspace_scope: Some(workspace_selector("default")),
        credential_keys: keys,
        ..Default::default()
    });
    request
        .extensions_mut()
        .insert(Principal::Operator(OperatorPrincipal {
            identity: Identity {
                subject: "long-key-operator".into(),
                display_name: None,
                roles: vec!["operator".into()],
                scopes: vec![],
                provider: IdentityProvider::Mtls,
            },
            certificate_sha256: "verified-test-certificate".into(),
        }));
    request
}

async fn public_delivery_and_export(mut state: Arc<ServerState>, source: RemoteProviderSource) {
    let keys = ["K".repeat(129), "K".repeat(256)];
    let expected = HashMap::from([
        (keys[0].clone(), "private-129-byte-key-value".to_string()),
        (keys[1].clone(), "private-256-byte-key-value".to_string()),
    ]);
    state
        .store
        .put_message(&crate::provider_profile_sources::stored_provider_profile(
            ProviderProfile {
                id: "long-keys".into(),
                credentials: keys
                    .iter()
                    .enumerate()
                    .map(|(index, key)| ProviderProfileCredential {
                        name: format!("token_{index}"),
                        env_vars: vec![key.clone()],
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            },
        ))
        .await
        .unwrap();
    let source = Arc::new(source);
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    let service = OpenShellService::new(state.clone());
    let created = service
        .create_provider(authed_request(CreateProviderRequest {
            workspace_scope: Some(workspace_selector("default")),
            provider: Some(Provider {
                metadata: Some(ObjectMeta {
                    name: "long-key-provider".into(),
                    ..Default::default()
                }),
                r#type: "long-keys".into(),
                credentials: expected.clone(),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
        .provider
        .unwrap();
    assert_eq!(created.credentials.len(), 2);
    assert!(
        created
            .credentials
            .values()
            .all(|value| value == "REDACTED")
    );
    assert!(created.credential_handles.is_empty());
    let stored = state
        .store
        .get_message::<Provider>(created.object_id())
        .await
        .unwrap()
        .unwrap();
    assert!(stored.credentials.is_empty());
    assert_eq!(stored.credential_handles.len(), 2);
    source.register_provider(&stored).unwrap();
    source
        .issuer()
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let delivered = source
        .resolve_provider_handles(&stored, current_time_ms())
        .await
        .unwrap();
    assert_eq!(delivered.values, expected);
    // The operator RPC must perform an export-purpose read rather than relying
    // on the delivery cache populated above.
    let exported = service
        .get_provider_credentials(export_request(keys.to_vec()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exported.credentials.len(), 2);
    for key in &keys {
        assert_eq!(exported.credentials[key].value, expected[key]);
        assert!(exported.credentials[key].expiration_time.is_none());
    }
    assert_eq!(
        service
            .get_provider_credentials(export_request(vec!["K".repeat(257)]))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        service
            .create_provider(authed_request(CreateProviderRequest {
                workspace_scope: Some(workspace_selector("default")),
                provider: Some(Provider {
                    metadata: Some(ObjectMeta {
                        name: "overlong-key-provider".into(),
                        ..Default::default()
                    }),
                    r#type: "long-keys".into(),
                    credentials: HashMap::from([("K".repeat(257), "rejected-value".into())]),
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(
        state
            .store
            .get_message_by_name::<Provider>("default", "overlong-key-provider")
            .await
            .unwrap()
            .is_none()
    );
    // Isolate the correlation limit from the owner limit: a valid owner and
    // reference do not make a 257-byte request ID acceptable to the client.
    let reference = source.decode(&stored.credential_handles[&keys[0]]).unwrap();
    assert_eq!(
        source
            .issuer()
            .resolve_secrets(wire::ResolveSecretsRequest {
                secrets: vec![wire::ResolveSecretRequest {
                    request_id: "K".repeat(257),
                    owner: Some(owner(&stored, &keys[0]).unwrap()),
                    reference: reference.reference,
                    expected_version: None,
                }],
                purpose: wire::ResolvePurpose::OperatorExport as i32,
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn remote_public_provider_delivers_and_exports_129_and_256_byte_credential_keys() {
    let state = test_server_state().await;
    let issuer = issuer::Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    public_delivery_and_export(state, source).await;
}

#[tokio::test]
async fn embedded_public_provider_delivers_and_exports_129_and_256_byte_credential_keys() {
    let state = test_server_state().await;
    let directory = tempfile::tempdir().unwrap();
    let database = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("issuer.db").display()
    );
    let crypto = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("issuer.key").display().to_string()),
    )]);
    let issuer = EmbeddedIssuer::new(
        &database,
        &state.store,
        &state.credentials,
        &crypto,
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    public_delivery_and_export(state, issuer.source.clone()).await;
    issuer.drain().await;
}
