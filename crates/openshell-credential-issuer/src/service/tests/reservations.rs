// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
fn request() -> wire::ReserveSecretRequest {
    wire::ReserveSecretRequest {
        owner: Some(wire_owner()),
        idempotency_key: "reserve".into(),
    }
}
async fn reserve(runtime: &Arc<Runtime>) -> wire::ReserveSecretResponse {
    runtime
        .clone()
        .reserve(test_scope(A), request(), idempotency("reserve").unwrap())
        .await
        .unwrap()
}
#[tokio::test]
async fn value_free_reservation_replays_original_identity_across_fill_and_revoke() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let reserved = reserve(&runtime).await;
    assert_eq!(reserved.version, 1);
    assert_eq!(reserve(&runtime).await, reserved);
    let mut renamed = request();
    renamed.owner.as_mut().unwrap().provider = "new display".into();
    assert_eq!(
        runtime
            .clone()
            .reserve(test_scope(A), renamed, idempotency("reserve").unwrap())
            .await
            .unwrap(),
        reserved
    );
    let inspected = runtime
        .resolve(
            &test_scope(A),
            resolve(
                &reserved.reference,
                wire::ResolvePurpose::MetadataInspection,
            ),
        )
        .await
        .unwrap();
    assert!(inspected.secrets[0].pending_value);
    assert!(inspected.secrets[0].value.is_empty());
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), 0);
    assert!(
        runtime
            .resolve(
                &test_scope(A),
                resolve(&reserved.reference, wire::ResolvePurpose::SandboxDelivery)
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), 0);
    let mut other = request();
    other.owner.as_mut().unwrap().credential_key = "OTHER".into();
    assert_eq!(
        runtime
            .clone()
            .reserve(test_scope(A), other, idempotency("reserve").unwrap())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        runtime
            .clone()
            .put(
                test_scope(A),
                wire::PutSecretRequest {
                    idempotency_key: "reserve".into(),
                    ..put()
                },
                idempotency("reserve").unwrap()
            )
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), 0);
    let filled = runtime
        .clone()
        .put(
            test_scope(A),
            wire::PutSecretRequest {
                reference: reserved.reference.clone(),
                expected_version: Some(1),
                idempotency_key: "fill".into(),
                ..put()
            },
            idempotency("fill").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(filled.version, 2);
    assert_eq!(filled.reference, reserved.reference);
    assert_eq!(reserve(&runtime).await, reserved);
    runtime
        .clone()
        .delete(
            test_scope(A),
            wire::DeleteSecretRequest {
                owner: Some(wire_owner()),
                reference: reserved.reference.clone(),
                expected_version: Some(2),
                idempotency_key: "revoke".into(),
            },
            idempotency("revoke").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reserve(&runtime).await, reserved);
    assert!(
        runtime
            .resolve(
                &test_scope(A),
                resolve(
                    &reserved.reference,
                    wire::ResolvePurpose::MetadataInspection
                )
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn revoking_known_pending_identity_fences_a_late_conditional_value_fill() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let reserved = reserve(&runtime).await;
    runtime
        .clone()
        .delete(
            test_scope(A),
            wire::DeleteSecretRequest {
                owner: Some(wire_owner()),
                reference: reserved.reference.clone(),
                expected_version: Some(1),
                idempotency_key: "abort".into(),
            },
            idempotency("abort").unwrap(),
        )
        .await
        .unwrap();
    let fill = wire::PutSecretRequest {
        reference: reserved.reference.clone(),
        expected_version: Some(1),
        idempotency_key: "late-fill".into(),
        ..put()
    };
    assert_eq!(
        runtime
            .clone()
            .put(test_scope(A), fill, idempotency("late-fill").unwrap())
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(reserve(&runtime).await, reserved);
    let foreign = runtime
        .clone()
        .reserve(test_scope(B), request(), idempotency("reserve").unwrap())
        .await
        .unwrap();
    assert_ne!(foreign.reference, reserved.reference);
    assert!(
        runtime
            .resolve(
                &test_scope(B),
                resolve(
                    &reserved.reference,
                    wire::ResolvePurpose::MetadataInspection
                )
            )
            .await
            .is_err()
    );
}
