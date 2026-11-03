// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::SecretOwner;
use crate::{remote_issuer::RemoteIssuer, service::tests::mtls::Server};
use tonic::Code;

#[tokio::test]
async fn detach_preserves_latest_bundle_versions_expiry_and_static_deletion_ownership() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    fixture
        .runtime()
        .rotate(
            test_scope(A),
            created.grant.clone(),
            idempotency("rotate-before-detach").unwrap(),
        )
        .await
        .unwrap();
    let before = values(&fixture, &created).await;
    assert_eq!(before.secrets[0].value, "first-2");
    let reads = fixture.resolves.load(Ordering::SeqCst);
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.resolves.load(Ordering::SeqCst),
        reads,
        "detaching must not resolve output values"
    );
    assert_eq!(values(&fixture, &created).await, before);
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach").unwrap(),
        )
        .await
        .unwrap();
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach-again").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Detached
    );
    assert_eq!(
        fixture
            .runtime()
            .ensure(test_scope(A), created.grant.clone(), 0)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .runtime()
            .rotate(
                test_scope(A),
                created.grant.clone(),
                idempotency("rotate-after-detach").unwrap()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .runtime()
            .delete(
                test_scope(A),
                created.grant.clone(),
                idempotency("delete-after-detach").unwrap()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    fixture.runtime().tick().await.unwrap();
    assert_eq!(
        values(&fixture, &created).await,
        before,
        "grant cleanup must not delete preserved outputs"
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
    fixture
        .store
        .runtime
        .clone()
        .delete(
            test_scope(A),
            store_wire::DeleteSecretRequest {
                owner: Some(owner()),
                reference: created.output_references["first"].clone(),
                expected_version: Some(3),
                idempotency_key: "delete-one-static".into(),
            },
            idempotency("delete-one-static").unwrap(),
        )
        .await
        .unwrap();
    let second = fixture
        .store
        .runtime
        .resolve(
            &test_scope(A),
            store_wire::ResolveSecretsRequest {
                purpose: store_wire::ResolvePurpose::OperatorExport as i32,
                secrets: vec![store_wire::ResolveSecretRequest {
                    request_id: "second".into(),
                    owner: Some(store_wire::SecretOwner {
                        credential_key: "TOKEN_TWO".into(),
                        ..owner()
                    }),
                    reference: created.output_references["second"].clone(),
                    expected_version: Some(3),
                }],
            },
        )
        .await
        .unwrap();
    assert_eq!(second.secrets[0].value, "second-2");
}

#[tokio::test]
async fn detach_pending_bundle_has_no_side_effect_and_can_be_retried_after_first_mint() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    assert_eq!(
        fixture
            .runtime()
            .detach(
                test_scope(A),
                created.grant.clone(),
                idempotency("detach").unwrap()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Pending
    );
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(values(&fixture, &created).await.secrets[0].value, "first-1");
}

#[tokio::test]
async fn authenticated_detach_serializes_with_admitted_rotation_and_survives_disconnect() {
    let fixture = Fixture::new().await;
    let server =
        Server::start_with_refresh(fixture.store.clone(), Some(fixture.service.clone())).await;
    let client = RemoteIssuer::connect(&server.config(A)).await.unwrap();
    let foreign = RemoteIssuer::connect(&server.config(B)).await.unwrap();
    assert!(
        client
            .list_strategies()
            .await
            .unwrap()
            .supports_grant_detach
    );
    let created = client.create_grant(request()).await.unwrap();
    client
        .ensure_fresh(wire::EnsureFreshRequest {
            grant: created.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap();
    assert_eq!(
        foreign
            .detach_grant(wire::DetachGrantRequest {
                grant: created.grant.clone(),
                idempotency_key: "forged".into()
            })
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    fixture.minter.block.store(true, Ordering::SeqCst);
    let rotate_client = client.clone();
    let grant = created.grant.clone();
    let rotation = tokio::spawn(async move {
        rotate_client
            .rotate_grant(wire::RotateGrantRequest {
                grant,
                idempotency_key: "in-flight".into(),
            })
            .await
    });
    fixture.minter.started.notified().await;
    let detach_client = client.clone();
    let request = wire::DetachGrantRequest {
        grant: created.grant.clone(),
        idempotency_key: "detach".into(),
    };
    let retry = request.clone();
    let detachment = tokio::spawn(async move { detach_client.detach_grant(request).await });
    tokio::task::yield_now().await;
    assert!(!detachment.is_finished());
    detachment.abort();
    fixture.minter.release.notify_one();
    rotation.await.unwrap().unwrap();
    client.detach_grant(retry).await.unwrap();
    assert_eq!(values(&fixture, &created).await.secrets[0].value, "first-2");
    fixture.runtime().tick().await.unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn detach_abandons_unpublished_known_result_without_replacing_last_published_values() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    let before = values(&fixture, &created).await;
    fixture.minter.fail_backend.store(true, Ordering::SeqCst);
    fixture
        .runtime()
        .rotate(
            test_scope(A),
            created.grant.clone(),
            idempotency("interrupted-publication").unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Publishing
    );
    fixture.minter.backend.store(false, Ordering::SeqCst);
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach").unwrap(),
        )
        .await
        .unwrap();
    fixture.runtime().tick().await.unwrap();
    assert_eq!(values(&fixture, &created).await, before);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn detach_rejects_a_revoked_sibling_without_releasing_other_output_bindings() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    let refs = fixture
        .runtime()
        .store
        .repository
        .references(&test_scope(A));
    refs.registry()
        .revoke(
            &created.output_references["second"],
            &SecretOwner {
                workspace: "default".into(),
                provider_id: owner().provider_id,
                credential_key: "TOKEN_TWO".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        fixture
            .runtime()
            .detach(
                test_scope(A),
                created.grant.clone(),
                idempotency("detach").unwrap()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Refreshed
    );
    assert_eq!(
        fixture
            .runtime()
            .binding_fences(
                &test_scope(A),
                &fixture
                    .runtime()
                    .load(&test_scope(A), &created.grant)
                    .await
                    .unwrap()
                    .state
            )
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn late_mint_after_lease_loss_cannot_change_a_detached_static_bundle() {
    let fixture = Fixture::new().await;
    let created = create(&fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), created.grant.clone(), 0)
        .await
        .unwrap();
    let before = values(&fixture, &created).await;
    fixture.minter.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let grant = created.grant.clone();
    let rotation = tokio::spawn(async move {
        runtime
            .rotate(test_scope(A), grant, idempotency("late-rotation").unwrap())
            .await
    });
    fixture.minter.started.notified().await;
    // Bypass local exclusion to model a former lease holder whose upstream
    // call returns after another replica permanently stopped the grant.
    fixture
        .runtime()
        .detach(
            test_scope(A),
            created.grant.clone(),
            idempotency("detach").unwrap(),
        )
        .await
        .unwrap();
    fixture.minter.release.notify_one();
    assert!(rotation.await.unwrap().is_err());
    fixture.runtime().tick().await.unwrap();
    assert_eq!(values(&fixture, &created).await, before);
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Detached
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
}
