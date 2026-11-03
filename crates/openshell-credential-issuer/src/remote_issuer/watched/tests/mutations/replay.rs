// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn grant_request() -> refresh::ReserveGrantRequest {
    refresh::ReserveGrantRequest {
        owner: Some(owner()),
        strategy: "custom:test".into(),
        outputs: outputs(),
        idempotency_key: "reserve-grant".into(),
        ..Default::default()
    }
}
fn fill_secrets(source: &WatchedIssuer, existing: usize) {
    for number in 0..REFERENCES - existing {
        source
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
}
fn fill_grants(source: &WatchedIssuer, existing: usize) {
    for number in 0..GRANTS - existing {
        source
            .track_grant(format!("active-grant-{number}"))
            .unwrap();
    }
}

#[test]
fn canonical_grant_reservation_intents_match_issuer_duration_rounding() {
    let mut first = grant_request();
    first.refresh_before = Some(prost_types::Duration {
        seconds: 0,
        nanos: 1,
    });
    first.max_lifetime = Some(prost_types::Duration {
        seconds: 60,
        nanos: 1,
    });
    let mut equivalent = first.clone();
    equivalent.refresh_before = Some(prost_types::Duration {
        seconds: 0,
        nanos: 1_000_000,
    });
    equivalent.max_lifetime = Some(prost_types::Duration {
        seconds: 61,
        nanos: 0,
    });
    assert_eq!(
        crate::remote_issuer::watched::mutations::grant_intent(&first).unwrap(),
        crate::remote_issuer::watched::mutations::grant_intent(&equivalent).unwrap()
    );
    equivalent.max_lifetime = Some(prost_types::Duration {
        seconds: 60,
        nanos: 0,
    });
    assert_ne!(
        crate::remote_issuer::watched::mutations::grant_intent(&first).unwrap(),
        crate::remote_issuer::watched::mutations::grant_intent(&equivalent).unwrap()
    );
}

#[tokio::test]
async fn observed_secret_reservation_replays_at_capacity_but_new_or_changed_intents_do_not() {
    let server = Server::start().await;
    server.calls.release.add_permits(1);
    let reserved = server.source.reserve_secret(reserve()).await.unwrap();
    fill_secrets(&server.source, 1);

    let mut changed = reserve();
    changed.idempotency_key = "unknown".into();
    assert_eq!(
        server
            .source
            .reserve_secret(changed)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    // Exercise every immutable owner field independently of the operation key.
    for field in 0..3 {
        let mut changed = reserve();
        let owner = changed.owner.as_mut().unwrap();
        match field {
            0 => owner.workspace = "other".into(),
            1 => owner.provider_id = "other".into(),
            _ => owner.credential_key = "OTHER".into(),
        }
        assert_eq!(
            server
                .source
                .reserve_secret(changed)
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    }
    // A previously registered ID is not evidence that this new intent owns it.
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 1);
    let mut replay = reserve();
    replay.owner.as_mut().unwrap().provider = "renamed audit display".into();
    server.calls.release.add_permits(1);
    assert_eq!(
        server.source.reserve_secret(replay.clone()).await.unwrap(),
        reserved
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 2);
    replay.owner.as_mut().unwrap().provider = "x".repeat(crate::remote_issuer::LIMIT);
    assert_eq!(
        server
            .source
            .reserve_secret(replay)
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    let state = server.source.inner.lock().unwrap();
    assert_eq!(state.secrets.len(), REFERENCES);
    assert_eq!(state.reserved_secrets, 0);
    assert_eq!(state.secrets[&reserved.reference].admissions, 0);
}

#[tokio::test]
async fn observed_grant_reservation_replays_at_both_limits_without_admitting_changed_intents() {
    let server = Server::start().await;
    let request = grant_request();
    server.calls.release.add_permits(1);
    let reserved = server.source.reserve_grant(request.clone()).await.unwrap();
    fill_secrets(&server.source, 2);
    fill_grants(&server.source, 1);
    let mut changed = Vec::new();
    let mut other = request.clone();
    other.idempotency_key = "unknown".into();
    changed.push(other);
    let mut other = request.clone();
    other.owner.as_mut().unwrap().provider_id = "other".into();
    changed.push(other);
    let mut other = request.clone();
    other.strategy = "custom:other".into();
    changed.push(other);
    let mut other = request.clone();
    other.outputs.insert("one".into(), "OTHER".into());
    changed.push(other);
    let mut other = request.clone();
    other.refresh_before = Some(prost_types::Duration {
        seconds: 1,
        nanos: 0,
    });
    changed.push(other);
    let mut other = request.clone();
    other.max_lifetime = Some(prost_types::Duration {
        seconds: 60,
        nanos: 0,
    });
    changed.push(other);
    for request in changed {
        assert_eq!(
            server
                .source
                .reserve_grant(request)
                .await
                .unwrap_err()
                .code(),
            Code::ResourceExhausted
        );
    }
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 1);
    // Rebuilding a map in reverse order must not change its canonical intent.
    let mut replay = request;
    replay.outputs = [("two".into(), "TWO".into()), ("one".into(), "ONE".into())].into();
    replay.owner.as_mut().unwrap().provider = "new audit display".into();
    replay.refresh_before = Some(prost_types::Duration {
        seconds: 300,
        nanos: 0,
    });
    replay.max_lifetime = Some(prost_types::Duration {
        seconds: 3600,
        nanos: 0,
    });
    server.calls.release.add_permits(1);
    assert_eq!(server.source.reserve_grant(replay).await.unwrap(), reserved);
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 2);
    let state = server.source.inner.lock().unwrap();
    assert_eq!(state.secrets.len(), REFERENCES);
    assert_eq!(state.grants.len(), GRANTS);
    assert_eq!((state.reserved_secrets, state.reserved_grants), (0, 0));
    assert!(state.secrets.values().all(|entry| entry.admissions == 0));
    assert!(state.grants.values().all(|entry| entry.admissions == 0));
}

#[tokio::test]
async fn replay_pins_a_retired_secret_until_cancellation_releases_its_capacity() {
    let server = Server::start().await;
    server.calls.release.add_permits(1);
    let reserved = server.source.reserve_secret(reserve()).await.unwrap();
    server.started().await;
    fill_secrets(&server.source, 1);
    let source = server.source.clone();
    let replay = tokio::spawn(async move { source.reserve_secret(reserve()).await });
    server.started().await;
    server
        .source
        .inner
        .lock()
        .unwrap()
        .retire_secret(&reserved.reference, 2);
    assert_eq!(
        server
            .source
            .track_secret(owner(), "competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    replay.abort();
    assert!(replay.await.unwrap_err().is_cancelled());
    assert_eq!(
        server.source.inner.lock().unwrap().secrets[&reserved.reference].admissions,
        0
    );
    server
        .source
        .track_secret(owner(), "competitor".into())
        .unwrap();
    assert!(
        !server
            .source
            .inner
            .lock()
            .unwrap()
            .secrets
            .contains_key(&reserved.reference)
    );
    // Reclaiming the binding also reclaims its receipt: no unknown bypass.
    assert_eq!(
        server
            .source
            .reserve_secret(reserve())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 2);
    server.calls.release.add_permits(1);
}

#[tokio::test]
async fn replay_pins_the_entire_retired_grant_bundle_until_cancellation() {
    let server = Server::start().await;
    server.calls.release.add_permits(1);
    let reserved = server.source.reserve_grant(grant_request()).await.unwrap();
    server.started().await;
    fill_secrets(&server.source, 2);
    fill_grants(&server.source, 1);
    let source = server.source.clone();
    let replay = tokio::spawn(async move { source.reserve_grant(grant_request()).await });
    server.started().await;
    {
        let mut state = server.source.inner.lock().unwrap();
        state.retire_grant(&reserved.grant, 2);
        for id in reserved.output_references.values() {
            state.retire_secret(id, 2);
        }
    }
    assert_eq!(
        server
            .source
            .track_secret(owner(), "competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        server
            .source
            .track_grant("competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    replay.abort();
    assert!(replay.await.unwrap_err().is_cancelled());
    {
        let state = server.source.inner.lock().unwrap();
        assert!(state.secrets.values().all(|entry| entry.admissions == 0));
        assert!(state.grants.values().all(|entry| entry.admissions == 0));
    }
    server
        .source
        .track_secret(owner(), "competitor".into())
        .unwrap();
    server.source.track_grant("competitor".into()).unwrap();
    assert!(
        !server
            .source
            .inner
            .lock()
            .unwrap()
            .grants
            .contains_key(&reserved.grant)
    );
    assert_eq!(
        server
            .source
            .reserve_grant(grant_request())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 2);
    server.calls.release.add_permits(1);
}

#[tokio::test]
async fn a_reclaimed_and_reregistered_output_cannot_authorize_zero_capacity_grant_replay() {
    let server = Server::start().await;
    server.calls.release.add_permits(1);
    let reserved = server.source.reserve_grant(grant_request()).await.unwrap();
    fill_secrets(&server.source, 2);
    let id = &reserved.output_references["one"];
    server.source.inner.lock().unwrap().retire_secret(id, 2);
    server
        .source
        .track_secret(owner(), "competitor".into())
        .unwrap();
    server
        .source
        .inner
        .lock()
        .unwrap()
        .retire_secret("competitor", 2);
    let mut bound = owner();
    bound.credential_key = "ONE".into();
    server.source.track_secret(bound, id.clone()).unwrap();
    assert_eq!(
        server
            .source
            .reserve_grant(grant_request())
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn admitted_replays_still_require_remote_authorization_and_release_pins_on_error() {
    let server = Server::start().await;
    server.calls.release.add_permits(2);
    let secret = server.source.reserve_secret(reserve()).await.unwrap();
    let grant = server.source.reserve_grant(grant_request()).await.unwrap();
    fill_secrets(&server.source, 3);
    fill_grants(&server.source, 1);
    server.calls.deny_reservation.store(true, Ordering::SeqCst);
    server.calls.release.add_permits(2);
    assert_eq!(
        server
            .source
            .reserve_secret(reserve())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        server
            .source
            .reserve_grant(grant_request())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 4);
    let state = server.source.inner.lock().unwrap();
    assert_eq!(state.secrets[&secret.reference].admissions, 0);
    assert_eq!(state.grants[&grant.grant].admissions, 0);
    assert!(state.secrets.values().all(|entry| entry.admissions == 0));
    assert_eq!((state.reserved_secrets, state.reserved_grants), (0, 0));
}

#[tokio::test]
async fn reservation_output_names_cannot_inflate_retained_replay_metadata() {
    let server = Server::start().await;
    let mut request = grant_request();
    request.outputs = [("x".repeat(129), "TOKEN".into())].into();
    assert_eq!(
        server
            .source
            .reserve_grant(request)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(server.calls.allocations.load(Ordering::SeqCst), 0);
}
