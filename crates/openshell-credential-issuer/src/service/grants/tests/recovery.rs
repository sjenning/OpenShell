// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::ReferenceStateStore;
use tonic::Code;

#[tokio::test]
async fn known_result_survives_backend_outage_and_new_runtime_without_another_mint() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.fail_backend.store(true, Ordering::SeqCst);
    let error = fixture
        .runtime()
        .ensure(test_scope(A), grant.grant.clone(), 0)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(!error.message().contains("private-backend"));
    let loaded = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    assert_eq!(loaded.state.phase, GrantPhase::Publishing);
    assert!(loaded.state.attempt.unwrap().encrypted_result.is_some());
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    fixture.minter.backend.store(false, Ordering::SeqCst);
    let restarted = CredentialRefreshService::new(
        &fixture.store,
        fixture.runtime().minters.clone(),
        fixture.runtime().spool.clone(),
    )
    .unwrap();
    restarted.runtime.tick().await.unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(values(&fixture, &grant).await.secrets[0].value, "first-1");
    restarted
        .runtime
        .rotate(
            test_scope(A),
            grant.grant,
            idempotency("after-recovery").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        *fixture.minter.seen.lock().unwrap(),
        vec!["initial-refresh", "rotated-1"]
    );
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_an_admitted_rotating_exchange() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let id = grant.grant.clone();
    let caller = tokio::spawn(async move { runtime.ensure(test_scope(A), id, 0).await });
    fixture.minter.started.notified().await;
    caller.abort();
    fixture.minter.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if fixture
                .runtime()
                .load(&test_scope(A), &grant.grant)
                .await
                .unwrap()
                .state
                .phase
                == GrantPhase::Refreshed
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(values(&fixture, &grant).await.secrets[0].value, "first-1");
}

#[tokio::test]
async fn unknown_outcomes_and_failed_rotation_receipts_never_replay_upstream() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.uncertain.store(true, Ordering::SeqCst);
    for nonce in ["uncertain", "uncertain", "another"] {
        let error = fixture
            .runtime()
            .rotate(
                test_scope(A),
                grant.grant.clone(),
                idempotency(nonce).unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(!error.message().contains("private-minter-error"));
    }
    fixture.runtime().tick().await.unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    let loaded = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    assert_eq!(loaded.state.phase, GrantPhase::Parked);
    assert_eq!(loaded.state.next_refresh_at_ms, i64::MAX);
}

#[tokio::test]
async fn uncertain_oauth_reauthorization_never_reuses_the_consumed_material() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.uncertain.store(true, Ordering::SeqCst);
    fixture.minter.oauth_uncertain.store(true, Ordering::SeqCst);
    for key in ["first", "second"] {
        assert!(
            fixture
                .runtime()
                .rotate(
                    test_scope(A),
                    grant.grant.clone(),
                    idempotency(key).unwrap()
                )
                .await
                .is_err()
        );
    }
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn create_rotate_and_static_put_share_gateway_idempotency_intent() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    assert_eq!(
        fixture
            .runtime()
            .rotate(test_scope(A), grant.grant, idempotency("create").unwrap())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    let put = store_wire::PutSecretRequest {
        owner: Some(owner()),
        reference: String::new(),
        value: "should-not-publish".into(),
        expiration_time: None,
        expected_version: None,
        idempotency_key: "create".into(),
    };
    assert_eq!(
        fixture
            .store
            .runtime
            .clone()
            .put(test_scope(A), put, idempotency("create").unwrap())
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn creation_replay_survives_strategy_removal_without_rebinding_outputs() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    let replacement = CredentialRefreshService::new(
        &fixture.store,
        Arc::new(MinterRegistry::default()),
        fixture.runtime().spool.clone(),
    )
    .unwrap();
    let replay = replacement
        .runtime
        .clone()
        .create(test_scope(A), request(), idempotency("create").unwrap())
        .await
        .unwrap();
    assert_eq!(replay, grant);
    assert!(
        replacement
            .runtime
            .ensure(test_scope(A), grant.grant.clone(), 0)
            .await
            .is_err()
    );
    assert_eq!(
        replacement
            .runtime
            .load(&test_scope(A), &grant.grant)
            .await
            .unwrap()
            .state
            .failure_code,
        "strategy_descriptor_changed"
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn late_known_response_cannot_publish_after_authorization_deletion() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let id = grant.grant.clone();
    let caller = tokio::spawn(async move { runtime.ensure(test_scope(A), id, 0).await });
    fixture.minter.started.notified().await;
    // Bypass the local lock to model a former holder losing its distributed
    // lease while its already-admitted upstream request is still active.
    fixture
        .runtime()
        .delete(
            test_scope(A),
            grant.grant.clone(),
            idempotency("delete").unwrap(),
        )
        .await
        .unwrap();
    fixture.minter.release.notify_one();
    assert!(caller.await.unwrap().is_err());
    fixture.runtime().tick().await.unwrap();
    let loaded = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    assert_eq!(loaded.state.phase, GrantPhase::Deleted);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    for binding in loaded.state.definition.outputs.values() {
        assert!(
            fixture
                .store
                .runtime
                .repository
                .references(&test_scope(A))
                .load(&binding.reference)
                .await
                .unwrap()
                .unwrap()
                .state
                .revoked
        );
    }
}

#[tokio::test]
async fn a_late_known_result_can_recover_the_same_parked_attempt_without_replaying_it() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    fixture.minter.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let id = grant.grant.clone();
    let caller = tokio::spawn(async move { runtime.ensure(test_scope(A), id, 0).await });
    fixture.minter.started.notified().await;
    let loaded = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    let mut state = loaded.state;
    state.phase = GrantPhase::Parked;
    state.version += 1;
    state.recovery_action = Some(RecoveryAction::Investigate);
    state.failure_code = "mint_outcome_unknown".into();
    state.next_refresh_at_ms = i64::MAX;
    let scope = test_scope(A);
    let (mutation, event) = fixture
        .store
        .runtime
        .repository
        .grants(&scope)
        .prepare(Some(loaded.revision), &state)
        .await
        .unwrap();
    fixture
        .store
        .runtime
        .repository
        .for_gateway(&scope)
        .commit(&[mutation], &event.into_iter().collect::<Vec<_>>())
        .await
        .unwrap();
    fixture.minter.release.notify_one();
    caller.await.unwrap().unwrap();
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    assert_eq!(values(&fixture, &grant).await.secrets[0].value, "first-1");
}

#[tokio::test]
async fn concurrent_freshness_requests_coalesce_one_attempt_and_fixed_output_set() {
    let fixture = Fixture::new().await;
    let grant = create(&fixture).await;
    let requests = (0..8)
        .map(|_| {
            let runtime = fixture.runtime();
            let id = grant.grant.clone();
            tokio::spawn(async move { runtime.ensure(test_scope(A), id, 0).await })
        })
        .collect::<Vec<_>>();
    for request in requests {
        request.await.unwrap().unwrap();
    }
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
    assert!(
        values(&fixture, &grant)
            .await
            .secrets
            .iter()
            .all(|secret| secret.version == 2)
    );
}
