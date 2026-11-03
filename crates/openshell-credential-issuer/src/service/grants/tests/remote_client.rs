// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{remote_issuer::RemoteIssuer, service::tests::mtls::Server};
use tonic::Code;

#[tokio::test]
async fn remote_client_negotiates_mtls_and_drives_both_private_services_without_auth_headers() {
    let fixture = Fixture::new().await;
    let server =
        Server::start_with_refresh(fixture.store.clone(), Some(fixture.service.clone())).await;
    let a = RemoteIssuer::connect(&server.config(A)).await.unwrap();
    let b = RemoteIssuer::connect(&server.config(B)).await.unwrap();
    assert!(a.capabilities().supports_metadata_inspection);
    assert_eq!(
        a.list_strategies().await.unwrap().strategies[0].name,
        "custom:test"
    );
    let mut secrets = a.watch_secrets(0).await.unwrap();
    let mut grants = a.watch_grants(0).await.unwrap();
    assert!(secrets.message().await.unwrap().unwrap().reset_required);
    assert!(secrets.message().await.unwrap().unwrap().checkpoint);
    assert!(grants.message().await.unwrap().unwrap().reset_required);
    assert!(grants.message().await.unwrap().unwrap().checkpoint);
    let created = a.create_grant(request()).await.unwrap();
    assert_eq!(a.create_grant(request()).await.unwrap(), created);
    assert_eq!(
        b.get_grant(wire::GetGrantRequest {
            grant: created.grant.clone()
        })
        .await
        .unwrap_err()
        .code(),
        Code::NotFound
    );
    let fresh = a
        .ensure_fresh(wire::EnsureFreshRequest {
            grant: created.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap()
        .status
        .unwrap();
    assert_eq!(fresh.state, "refreshed");
    assert_eq!(
        a.get_grant(wire::GetGrantRequest {
            grant: created.grant.clone()
        })
        .await
        .unwrap()
        .status
        .unwrap(),
        fresh
    );
    let resolved = a
        .resolve_secrets(store_wire::ResolveSecretsRequest {
            secrets: vec![store_wire::ResolveSecretRequest {
                request_id: "one".into(),
                owner: Some(store_wire::SecretOwner {
                    credential_key: "TOKEN_ONE".into(),
                    ..owner()
                }),
                reference: created.output_references["first"].clone(),
                expected_version: Some(2),
            }],
            purpose: store_wire::ResolvePurpose::SandboxDelivery as i32,
        })
        .await
        .unwrap();
    assert_eq!(resolved.secrets[0].value, "first-1");
    assert!(!format!("{resolved:?}").contains("first-1"));
    let rotation = wire::RotateGrantRequest {
        grant: created.grant.clone(),
        idempotency_key: "rotation".into(),
    };
    let rotated = a.rotate_grant(rotation.clone()).await.unwrap();
    assert_eq!(a.rotate_grant(rotation).await.unwrap(), rotated);
    let static_secret = a
        .put_secret(store_wire::PutSecretRequest {
            owner: Some(owner()),
            value: "static-private".into(),
            idempotency_key: "static".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(static_secret.version, 1);
    a.delete_secret(store_wire::DeleteSecretRequest {
        owner: Some(owner()),
        reference: static_secret.reference,
        expected_version: Some(1),
        idempotency_key: "delete-static".into(),
    })
    .await
    .unwrap();
    a.delete_grant(wire::DeleteGrantRequest {
        grant: created.grant.clone(),
        idempotency_key: "delete-grant".into(),
    })
    .await
    .unwrap();
    fixture.runtime().tick().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = secrets.message().await.unwrap().unwrap();
            if event.reference == created.output_references["first"] && event.revoked {
                break;
            }
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = grants.message().await.unwrap().unwrap();
            if event.grant == created.grant && event.deleted {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
}
