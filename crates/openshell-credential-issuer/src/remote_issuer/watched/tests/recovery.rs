// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn inspect(inner: &Inner, references: &[String]) {
    let mut inputs = store::ResolveSecretsRequest {
        purpose: store::ResolvePurpose::MetadataInspection as i32,
        ..Default::default()
    };
    let mut values = store::ResolveSecretsResponse::default();
    for id in references {
        let mut input = request(id).secrets.remove(0);
        input.expected_version = None;
        inputs.secrets.push(input);
        let mut value = response(id, "").secrets.remove(0);
        value.cache_ttl = Some(prost_types::Duration::default());
        values.secrets.push(value);
    }
    let before = inner.observe_secrets(&inputs).unwrap();
    cache::record(inner, &inputs, &mut values, &before).unwrap();
}

#[tokio::test]
async fn multibatch_recovery_notifies_after_the_last_metadata_batch_without_fencing_values() {
    let inner = Arc::new(inner());
    let source = WatchedIssuer {
        inner: inner.clone(),
        _workers: Arc::new(Workers(Vec::new())),
    };
    let references: Vec<_> = (0..65).map(|number| format!("ref-{number}")).collect();
    let batch = usize::try_from(inner.client.capabilities().max_batch_size).unwrap();
    assert!(references.len() > batch);
    for ids in references.chunks(batch) {
        inspect(&inner, ids);
    }
    inner.ready(ChangeKind::Secrets).unwrap();
    inner.ready(ChangeKind::Grants).unwrap();
    let mut health = source.health_changes();
    let initial = *health.borrow_and_update();

    // A local mutation invalidates snapshots without disconnecting either
    // stream. Delivery consumers see this generation on the first batch.
    inner.invalidate_values().unwrap();
    inspect(&inner, &references[..batch]);
    let partial = *health.borrow_and_update();
    assert_ne!(partial, initial);
    assert!(partial.synchronized());
    let owner = request(&references[batch]).secrets.remove(0).owner.unwrap();
    assert_eq!(
        source
            .known_secret(&owner, &references[batch])
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    inspect(&inner, &references[batch..]);
    assert_eq!(*health.borrow_and_update(), partial);

    // Both completing a checkpoint and an idle checkpoint in the other stream
    // must leave an otherwise valid value RPC eligible for cache publication.
    let before = inner.observe_secrets(&request(&references[0])).unwrap();
    inner.ready(ChangeKind::Secrets).unwrap();
    let recovered = *health.borrow_and_update();
    assert_ne!(recovered, partial);
    assert!(source.known_secret(&owner, &references[batch]).is_ok());
    inner.ready(ChangeKind::Secrets).unwrap();
    inner.ready(ChangeKind::Grants).unwrap();
    assert_eq!(*health.borrow_and_update(), recovered);
    let mut values = response(&references[0], "fresh");
    cache::record(&inner, &request(&references[0]), &mut values, &before).unwrap();
    assert!(values.secrets[0].cache_ttl.as_ref().unwrap().seconds > 0);
    assert!(
        cache::get(&inner, &request(&references[0]))
            .unwrap()
            .is_some()
    );
    inner.ready(ChangeKind::Secrets).unwrap();
    assert_eq!(*health.borrow_and_update(), recovered);
}

#[tokio::test]
async fn final_grant_recovery_is_distinct_from_partial_status_publications() {
    let inner = inner();
    inner.track_grant("one".into()).unwrap();
    inner.track_grant("two".into()).unwrap();
    let mut health = inner.health.subscribe();
    for id in ["one", "two"] {
        let before = inner.observe_grant(id).unwrap();
        cache::grant(
            &inner,
            &refresh::GrantStatus {
                grant: id.into(),
                version: 1,
                state: "pending".into(),
                ..Default::default()
            },
            &before,
        )
        .unwrap();
        let observed = *health.borrow_and_update();
        if id == "one" {
            inner.ready(ChangeKind::Grants).unwrap();
            assert_eq!(*health.borrow_and_update(), observed);
        }
    }
    let partial = *health.borrow_and_update();
    inner.ready(ChangeKind::Grants).unwrap();
    let complete = *health.borrow_and_update();
    assert_ne!(complete, partial);
    inner.ready(ChangeKind::Grants).unwrap();
    assert_eq!(*health.borrow_and_update(), complete);
    let before = inner.observe_grant("one").unwrap();
    inner
        .mutation_status(
            before,
            Some(&refresh::GrantStatus {
                grant: "one".into(),
                version: 1,
                state: "pending".into(),
                ..Default::default()
            }),
            false,
        )
        .unwrap();
    inner.ready(ChangeKind::Grants).unwrap();
    assert_eq!(*health.borrow_and_update(), complete);
}

#[tokio::test]
async fn activation_event_recovers_transient_missing_grants_but_never_terminal_ones() {
    let inner = inner();
    inner.track_grant("imported".into()).unwrap();
    {
        let mut state = inner.lock().unwrap();
        state.retire_grant("imported", 0);
        state.grants.get_mut("imported").unwrap().terminal = false;
    }
    controller::grant_event(
        &inner,
        &refresh::WatchGrantsResponse {
            grant: "imported".into(),
            version: 12,
            sequence: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!inner.lock().unwrap().grants["imported"].gone);
    let before = inner.observe_grant("imported").unwrap();
    cache::grant(
        &inner,
        &refresh::GrantStatus {
            grant: "imported".into(),
            state: "refreshed".into(),
            version: 12,
            ..Default::default()
        },
        &before,
    )
    .unwrap();
    assert!(inner.lock().unwrap().grants["imported"].metadata.is_some());
    controller::grant_event(
        &inner,
        &refresh::WatchGrantsResponse {
            grant: "imported".into(),
            version: 13,
            sequence: 2,
            deleted: true,
            ..Default::default()
        },
    )
    .unwrap();
    controller::grant_event(
        &inner,
        &refresh::WatchGrantsResponse {
            grant: "imported".into(),
            version: 14,
            sequence: 3,
            ..Default::default()
        },
    )
    .unwrap();
    let state = inner.lock().unwrap();
    assert!(state.grants["imported"].gone);
    assert!(state.grants["imported"].terminal);
}
