// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    remote_issuer::{IssuerChange, RemoteIssuer, WatchedIssuer},
    service::tests::mtls::Server,
};
use tonic::Code;
fn batch(created: &wire::CreateGrantResponse, version: u64) -> store_wire::ResolveSecretsRequest {
    store_wire::ResolveSecretsRequest {
        secrets: [("first", "TOKEN_ONE"), ("second", "TOKEN_TWO")]
            .into_iter()
            .map(|(id, key)| store_wire::ResolveSecretRequest {
                request_id: id.into(),
                owner: Some(store_wire::SecretOwner {
                    credential_key: key.into(),
                    ..owner()
                }),
                reference: created.output_references[id].clone(),
                expected_version: Some(version),
            })
            .collect(),
        purpose: store_wire::ResolvePurpose::SandboxDelivery as i32,
    }
}
#[tokio::test]
async fn watched_client_caches_complete_owned_versioned_batches_and_invalidates_on_rotation() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    let server =
        Server::start_with_refresh(fixture.store.clone(), Some(fixture.service.clone())).await;
    let source = WatchedIssuer::new(RemoteIssuer::connect(&server.config(A)).await.unwrap());
    for input in batch(&created, 2).secrets {
        source
            .track_secret(input.owner.unwrap(), input.reference)
            .unwrap();
    }
    source.track_grant(created.grant.clone()).unwrap();
    let missing = uuid::Uuid::new_v4().to_string();
    source.track_secret(owner(), missing.clone()).unwrap();
    source.track_grant(missing.clone()).unwrap();
    source
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let metadata = source
        .known_secret(
            &store_wire::SecretOwner {
                credential_key: "TOKEN_ONE".into(),
                ..owner()
            },
            &created.output_references["first"],
        )
        .unwrap();
    assert!(metadata.value.is_empty());
    assert_eq!(
        source.known_secret(&owner(), &missing).unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(
        source.known_grant(&missing).unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(metadata.version, 2);
    assert_eq!(
        source.known_grant(&created.grant).unwrap().state,
        "refreshed"
    );
    let first = source.resolve_secrets(batch(&created, 2)).await.unwrap();
    assert_eq!(first.secrets[0].value, "first-1");
    let reads = fixture.resolves.load(Ordering::SeqCst);
    fixture.fail_resolves.store(true, Ordering::SeqCst);
    let mut renamed = batch(&created, 2);
    for input in &mut renamed.secrets {
        input.request_id.push_str("-new");
        input.owner.as_mut().unwrap().provider = "renamed-display".into();
    }
    let cached = source.resolve_secrets(renamed).await.unwrap();
    assert_eq!(cached.secrets[0].request_id, "first-new");
    assert_eq!(cached.secrets[0].value, "first-1");
    assert_eq!(fixture.resolves.load(Ordering::SeqCst), reads);
    let mut export = batch(&created, 2);
    export.purpose = store_wire::ResolvePurpose::OperatorExport as i32;
    assert_eq!(
        source.resolve_secrets(export).await.unwrap_err().code(),
        Code::Unavailable
    );
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        source
            .resolve_secrets(batch(&created, 2))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    fixture.fail_resolves.store(false, Ordering::SeqCst);
    source.resolve_secrets(batch(&created, 2)).await.unwrap();
    let mut events = source.changes();
    fixture.fail_resolves.store(true, Ordering::SeqCst);
    server.disconnect();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(events.recv().await.unwrap(), IssuerChange::Unknown(_)) {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(!source.health().unwrap().synchronized());
    assert_eq!(
        source
            .resolve_secrets(batch(&created, 2))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    fixture.fail_resolves.store(false, Ordering::SeqCst);
    fixture
        .runtime()
        .rotate(
            test_scope(A),
            created.grant.clone(),
            idempotency("rotate-watched").unwrap(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let IssuerChange::Secret {
                reference, version, ..
            } = events.recv().await.unwrap()
                && reference == created.output_references["first"]
                && version == 3
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    fixture.fail_resolves.store(true, Ordering::SeqCst);
    source
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        source
            .known_secret(
                &store_wire::SecretOwner {
                    credential_key: "TOKEN_ONE".into(),
                    ..owner()
                },
                &created.output_references["first"]
            )
            .unwrap()
            .version,
        3
    );
    assert_eq!(
        source
            .resolve_secrets(batch(&created, 2))
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        source
            .resolve_secrets(batch(&created, 3))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    fixture.fail_resolves.store(false, Ordering::SeqCst);
    let current = source.resolve_secrets(batch(&created, 3)).await.unwrap();
    assert_eq!(current.secrets[0].value, "first-2");
    assert_eq!(current.secrets[1].value, "second-2");
    assert!(!format!("{source:?}").contains("first-2"));
}
