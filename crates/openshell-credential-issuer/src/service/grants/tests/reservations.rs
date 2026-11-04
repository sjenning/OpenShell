// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use tonic::Code;
pub(super) fn reservation() -> wire::ReserveGrantRequest {
    let request = request();
    wire::ReserveGrantRequest {
        owner: request.owner,
        strategy: request.strategy,
        outputs: request.outputs,
        refresh_before: request.refresh_before,
        max_lifetime: request.max_lifetime,
        idempotency_key: "reserve".into(),
    }
}
pub(super) fn initialization(grant: &str) -> wire::InitializeGrantRequest {
    let request = request();
    wire::InitializeGrantRequest {
        grant: grant.into(),
        config: request.config,
        secret_material: request.secret_material,
        idempotency_key: "initialize".into(),
    }
}
async fn reserve(fixture: &Fixture) -> wire::ReserveGrantResponse {
    fixture
        .runtime()
        .reserve(test_scope(A), reservation(), "reserve".into())
        .await
        .unwrap()
}

#[tokio::test]
async fn create_and_reserve_share_the_256_byte_output_credential_key_bound() {
    let fixture = Fixture::new().await;
    for length in [129, 256] {
        // Exercise a sibling binding independently of the primary owner's
        // credential key, which already has its own 256-byte admission bound.
        let credential_key = "K".repeat(length);
        let mut create = request();
        create
            .outputs
            .insert("second".into(), credential_key.clone());
        let created = fixture
            .runtime()
            .create(test_scope(A), create, format!("create-long-{length}"))
            .await
            .unwrap();
        let mut reserve = reservation();
        reserve
            .outputs
            .insert("second".into(), credential_key.clone());
        let reserved = fixture
            .runtime()
            .reserve(test_scope(A), reserve, format!("reserve-long-{length}"))
            .await
            .unwrap();
        for grant in [&created.grant, &reserved.grant] {
            let loaded = fixture.runtime().load(&test_scope(A), grant).await.unwrap();
            assert_eq!(
                loaded.state.definition.outputs["second"].credential_key,
                credential_key
            );
        }
    }
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn create_and_reserve_reject_overlong_blank_padded_and_control_output_keys() {
    let fixture = Fixture::new().await;
    for (index, credential_key) in [
        "K".repeat(257),
        String::new(),
        " TOKEN".into(),
        "TOKEN ".into(),
        "TOKEN\nVALUE".into(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut create = request();
        create
            .outputs
            .insert("second".into(), credential_key.clone());
        assert_eq!(
            fixture
                .runtime()
                .create(test_scope(A), create, format!("create-invalid-{index}"))
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        let mut reserve = reservation();
        reserve.outputs.insert("second".into(), credential_key);
        assert_eq!(
            fixture
                .runtime()
                .reserve(test_scope(A), reserve, format!("reserve-invalid-{index}"))
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.resolves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn descriptor_changes_reject_initialization_before_any_backend_access() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    let runtime = fixture.runtime();
    let replacement = Arc::new(GrantRuntime {
        store: runtime.store.clone(),
        minters: Arc::new(MinterRegistry::default()),
        spool: runtime.spool.clone(),
    });
    fixture.minter.backend.store(true, Ordering::SeqCst);
    assert_eq!(
        replacement
            .initialize(
                test_scope(A),
                initialization(&reserved.grant),
                "initialize".into()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(fixture.resolves.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        runtime
            .load(&test_scope(A), &reserved.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Reserved
    );
}
#[tokio::test]
async fn reservation_and_replay_are_value_free_and_cannot_mint() {
    let fixture = Fixture::new().await;
    fixture.minter.backend.store(true, Ordering::SeqCst);
    fixture.fail_resolves.store(true, Ordering::SeqCst);
    let reserved = reserve(&fixture).await;
    assert_eq!(reserve(&fixture).await, reserved);
    fixture.runtime().tick().await.unwrap();
    let loaded = fixture
        .runtime()
        .load(&test_scope(A), &reserved.grant)
        .await
        .unwrap();
    assert_eq!(loaded.state.phase, GrantPhase::Reserved);
    assert!(loaded.state.material.is_empty());
    assert!(loaded.state.definition.config_backing.is_empty());
    assert_eq!(
        fixture
            .runtime()
            .ensure(test_scope(A), reserved.grant.clone(), 0)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .runtime()
            .rotate(test_scope(A), reserved.grant.clone(), "rotate".into())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let metadata = fixture
        .store
        .runtime
        .resolve(
            &test_scope(A),
            store_wire::ResolveSecretsRequest {
                secrets: vec![store_wire::ResolveSecretRequest {
                    request_id: "metadata".into(),
                    owner: Some(owner()),
                    reference: reserved.output_references["first"].clone(),
                    expected_version: Some(1),
                }],
                purpose: store_wire::ResolvePurpose::MetadataInspection as i32,
            },
        )
        .await
        .unwrap();
    assert!(
        metadata
            .secrets
            .iter()
            .all(|secret| secret.pending_value && secret.value.is_empty() && secret.version == 1)
    );
    assert_eq!(fixture.resolves.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn reserved_identity_pins_owner_outputs_and_the_shared_operation_namespace() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    let mut renamed = reservation();
    renamed.owner.as_mut().unwrap().provider = "renamed".into();
    assert_eq!(
        fixture
            .runtime()
            .reserve(test_scope(A), renamed, "reserve".into())
            .await
            .unwrap(),
        reserved
    );
    let mut wrong = reservation();
    wrong.owner.as_mut().unwrap().provider_id = "other".into();
    assert_eq!(
        fixture
            .runtime()
            .reserve(test_scope(A), wrong, "reserve".into())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let mut changed = reservation();
    changed.outputs.insert("first".into(), "OTHER".into());
    assert_eq!(
        fixture
            .runtime()
            .reserve(test_scope(A), changed, "reserve".into())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        fixture
            .runtime()
            .create(test_scope(A), request(), "reserve".into())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        fixture
            .runtime()
            .initialize(
                test_scope(A),
                initialization(&reserved.grant),
                "reserve".into()
            )
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let other = fixture
        .runtime()
        .reserve(test_scope(B), reservation(), "reserve".into())
        .await
        .unwrap();
    assert_ne!(other.grant, reserved.grant);
    assert_eq!(
        fixture
            .runtime()
            .initialize(
                test_scope(B),
                initialization(&reserved.grant),
                "initialize".into()
            )
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
#[tokio::test]
async fn initialization_is_atomic_one_shot_and_replays_after_mint_and_deletion() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    let request = initialization(&reserved.grant);
    let initialized = fixture
        .runtime()
        .initialize(test_scope(A), request.clone(), "initialize".into())
        .await
        .unwrap();
    assert_eq!(initialized.status.as_ref().unwrap().version, 2);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .runtime()
            .initialize(test_scope(A), request.clone(), "initialize".into())
            .await
            .unwrap(),
        initialized
    );
    let mut changed = request.clone();
    changed
        .secret_material
        .insert("refresh_token".into(), "changed-secret".into());
    assert_eq!(
        fixture
            .runtime()
            .initialize(test_scope(A), changed, "initialize".into())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        fixture
            .runtime()
            .initialize(test_scope(A), request.clone(), "second-key".into())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    fixture
        .runtime()
        .ensure(test_scope(A), reserved.grant.clone(), 0)
        .await
        .unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(reserve(&fixture).await, reserved);
    fixture
        .runtime()
        .delete(test_scope(A), reserved.grant.clone(), "delete".into())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .runtime()
            .initialize(test_scope(A), request, "initialize".into())
            .await
            .unwrap(),
        initialized
    );
    assert_eq!(reserve(&fixture).await, reserved);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn deletion_of_a_reservation_fences_late_initialization() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    fixture
        .runtime()
        .delete(test_scope(A), reserved.grant.clone(), "delete".into())
        .await
        .unwrap();
    fixture.runtime().tick().await.unwrap();
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &reserved.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Deleted
    );
    assert_eq!(
        fixture
            .runtime()
            .initialize(
                test_scope(A),
                initialization(&reserved.grant),
                "late".into()
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(reserve(&fixture).await, reserved);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn failed_initialization_preserves_a_value_free_reservation_for_safe_retry() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    let mut invalid = initialization(&reserved.grant);
    invalid.secret_material.clear();
    assert_eq!(
        fixture
            .runtime()
            .initialize(test_scope(A), invalid, "initialize".into())
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    fixture.minter.backend.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .runtime()
            .initialize(
                test_scope(A),
                initialization(&reserved.grant),
                "initialize".into()
            )
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(
        fixture
            .runtime()
            .load(&test_scope(A), &reserved.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Reserved
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
    fixture.minter.backend.store(false, Ordering::SeqCst);
    fixture
        .runtime()
        .initialize(
            test_scope(A),
            initialization(&reserved.grant),
            "initialize".into(),
        )
        .await
        .unwrap();
    let scope = test_scope(A);
    let repository = fixture.runtime().store.repository.for_gateway(&scope);
    for kind in [
        crate::repository::grants::KIND,
        super::super::super::IDEMPOTENCY_KIND,
    ] {
        for (_, record) in repository.list(kind, None, 64).await.unwrap() {
            let metadata = String::from_utf8(record.payload).unwrap();
            assert!(!metadata.contains("private-audience"));
            assert!(!metadata.contains("initial-refresh"));
        }
    }
}
#[tokio::test]
async fn concurrent_initializers_cannot_replace_each_others_material() {
    let fixture = Fixture::new().await;
    let reserved = reserve(&fixture).await;
    let first = initialization(&reserved.grant);
    let mut second = first.clone();
    second
        .secret_material
        .insert("refresh_token".into(), "alternative-refresh".into());
    let (a, b) = tokio::join!(
        fixture
            .runtime()
            .initialize(test_scope(A), first, "first".into()),
        fixture
            .runtime()
            .initialize(test_scope(A), second, "second".into())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let error = if let Err(error) = a {
        error
    } else {
        b.unwrap_err()
    };
    assert!(matches!(
        error.code(),
        Code::FailedPrecondition | Code::Aborted
    ));
    fixture
        .runtime()
        .ensure(test_scope(A), reserved.grant, 0)
        .await
        .unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn mtls_client_and_watches_support_reserved_grant_handoffs() {
    use crate::{
        remote_issuer::{RemoteIssuer, WatchedIssuer},
        service::tests::mtls::Server,
    };
    let fixture = Fixture::new().await;
    let server =
        Server::start_with_refresh(fixture.store.clone(), Some(fixture.service.clone())).await;
    let raw = RemoteIssuer::connect(&server.config(A)).await.unwrap();
    let issuer = WatchedIssuer::new(raw);
    let reserved = issuer.reserve_grant(reservation()).await.unwrap();
    issuer
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        issuer.known_grant(&reserved.grant).unwrap().state,
        "reserved"
    );
    let initialized = issuer
        .initialize_grant(initialization(&reserved.grant))
        .await
        .unwrap();
    assert_eq!(initialized.status.unwrap().state, "pending");
    let fresh = issuer
        .ensure_fresh(wire::EnsureFreshRequest {
            grant: reserved.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap();
    assert_eq!(fresh.status.unwrap().state, "refreshed");
    assert_eq!(issuer.reserve_grant(reservation()).await.unwrap(), reserved);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
}
