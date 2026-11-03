// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::service::tests::mtls::Server;
use tonic::{Code, Request};

fn resolve(
    grant: &wire::CreateGrantResponse,
    purpose: store_wire::ResolvePurpose,
) -> store_wire::ResolveSecretsRequest {
    store_wire::ResolveSecretsRequest {
        secrets: [("first", "TOKEN_ONE"), ("second", "TOKEN_TWO")]
            .into_iter()
            .map(|(name, key)| store_wire::ResolveSecretRequest {
                request_id: name.into(),
                owner: Some(store_wire::SecretOwner {
                    credential_key: key.into(),
                    ..owner()
                }),
                reference: grant.output_references[name].clone(),
                expected_version: None,
            })
            .collect(),
        purpose: purpose as i32,
    }
}
#[tokio::test]
async fn authenticated_refresh_rpc_exposes_only_status_and_fixed_store_references() {
    let fixture = Fixture::new().await;
    let server =
        Server::start_with_refresh(fixture.store.clone(), Some(fixture.service.clone())).await;
    let channel = server.channel(A).await;
    let mut a = wire::credential_refresh_client::CredentialRefreshClient::new(channel.clone());
    let mut store = store_wire::credential_store_client::CredentialStoreClient::new(channel);
    let mut b =
        wire::credential_refresh_client::CredentialRefreshClient::new(server.channel(B).await);
    let strategies = a
        .list_strategies(wire::ListStrategiesRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(strategies.strategies[0].name, "custom:test");
    let created = a.create_grant(request()).await.unwrap().into_inner();
    assert_eq!(
        a.create_grant(request()).await.unwrap().into_inner(),
        created
    );
    let metadata = store
        .resolve_secrets(resolve(
            &created,
            store_wire::ResolvePurpose::MetadataInspection,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        metadata
            .secrets
            .iter()
            .all(|secret| secret.pending_value && secret.value.is_empty())
    );
    let mut forged = Request::new(wire::GetGrantRequest {
        grant: created.grant.clone(),
    });
    forged
        .metadata_mut()
        .insert("x-gateway-identity", A.parse().unwrap());
    assert_eq!(
        b.get_grant(forged).await.unwrap_err().code(),
        Code::NotFound
    );
    let mut stream = a
        .watch_grants(wire::WatchGrantsRequest { after_sequence: 0 })
        .await
        .unwrap()
        .into_inner();
    assert!(stream.message().await.unwrap().unwrap().reset_required);
    let status = a
        .ensure_fresh(wire::EnsureFreshRequest {
            grant: created.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap()
        .into_inner()
        .status
        .unwrap();
    assert_eq!(status.state, "refreshed");
    let resolved = store
        .resolve_secrets(resolve(
            &created,
            store_wire::ResolvePurpose::OperatorExport,
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(
        resolved
            .secrets
            .iter()
            .all(|secret| secret.version == 2 && !secret.value.is_empty())
    );
    let event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = stream.message().await.unwrap().unwrap();
            if !event.checkpoint && !event.reset_required {
                break event;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(event.grant, created.grant);
    assert!(event.version > 1);
    let rotation = wire::RotateGrantRequest {
        grant: created.grant.clone(),
        idempotency_key: "rotate".into(),
    };
    let first = a.rotate_grant(rotation.clone()).await.unwrap().into_inner();
    assert_eq!(
        a.rotate_grant(rotation.clone()).await.unwrap().into_inner(),
        first
    );
    let other = b.create_grant(request()).await.unwrap().into_inner();
    assert_ne!(other.grant, created.grant);
    a.delete_grant(wire::DeleteGrantRequest {
        grant: created.grant.clone(),
        idempotency_key: "delete".into(),
    })
    .await
    .unwrap();
    assert_eq!(a.rotate_grant(rotation).await.unwrap().into_inner(), first);
    assert_eq!(
        store
            .resolve_secrets(resolve(
                &created,
                store_wire::ResolvePurpose::SandboxDelivery
            ))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let mut unknown = wire::credential_refresh_client::CredentialRefreshClient::new(
        server
            .channel("spiffe://test.example/issuer/not-gateway")
            .await,
    );
    assert_eq!(
        unknown
            .list_strategies(wire::ListStrategiesRequest {})
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        unknown.create_grant(request()).await.unwrap_err().code(),
        Code::PermissionDenied
    );
}
