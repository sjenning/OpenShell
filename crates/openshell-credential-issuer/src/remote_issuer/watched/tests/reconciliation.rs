// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
async fn resets_retry_missing_authorization_but_preserve_immutable_terminal_fences() {
    let inner = inner();
    let owner = request("ref").secrets.remove(0).owner.unwrap();
    for id in ["missing", "revoked"] {
        inner.track_secret(owner.clone(), id.into()).unwrap();
        inner.track_grant(id.into()).unwrap();
    }
    {
        let mut state = inner.lock().unwrap();
        state.retire_secret("missing", 0);
        state.secrets.get_mut("missing").unwrap().terminal = false;
        state.retire_grant("missing", 0);
        state.grants.get_mut("missing").unwrap().terminal = false;
        state.retire_secret("revoked", 2);
        state.retire_grant("revoked", 2);
    }
    inner.unknown(ChangeKind::Secrets).unwrap();
    inner.unknown(ChangeKind::Grants).unwrap();
    let state = inner.lock().unwrap();
    assert!(!state.secrets["missing"].gone);
    assert!(!state.grants["missing"].gone);
    assert!(state.secrets["revoked"].gone);
    assert!(state.grants["revoked"].gone);
}
#[tokio::test]
async fn batch_admission_never_forgets_a_requested_tombstone_or_partially_inserts_siblings() {
    let inner = inner();
    let owner = request("ref").secrets.remove(0).owner.unwrap();
    inner.track_secret(owner.clone(), "revoked".into()).unwrap();
    inner.lock().unwrap().retire_secret("revoked", 2);
    for number in 0..REFERENCES - 1 {
        inner
            .track_secret(owner.clone(), format!("active-{number}"))
            .unwrap();
    }
    let mut batch = request("revoked");
    batch.secrets.extend(request("new").secrets);
    assert_eq!(
        inner.observe_secrets(&batch).err().unwrap().code(),
        Code::ResourceExhausted
    );
    let state = inner.lock().unwrap();
    assert!(state.secrets["revoked"].gone);
    assert!(!state.secrets.contains_key("new"));
    assert_eq!(state.secrets.len(), REFERENCES);
}
#[tokio::test]
async fn terminal_grant_inspection_invalidates_deleted_outputs_but_not_detached_outputs() {
    for (terminal, cache_survives) in [("deleted", false), ("detached", true)] {
        let inner = inner();
        let before = inner.observe_secrets(&request("output")).unwrap();
        cache::record(
            &inner,
            &request("output"),
            &mut response("output", "value"),
            &before,
        )
        .unwrap();
        let before = inner.observe_grant("grant").unwrap();
        cache::grant(
            &inner,
            &refresh::GrantStatus {
                grant: "grant".into(),
                version: 2,
                state: terminal.into(),
                ..Default::default()
            },
            &before,
        )
        .unwrap();
        assert_eq!(
            cache::get(&inner, &request("output")).unwrap().is_some(),
            cache_survives
        );
        assert_eq!(
            inner.lock().unwrap().secrets["output"].metadata.is_some(),
            cache_survives
        );
        assert!(inner.lock().unwrap().grants["grant"].gone);
    }
}
#[tokio::test]
async fn independent_watch_events_do_not_starve_metadata_reconciliation() {
    let inner = inner();
    let secrets = inner.observe_secrets(&request("ref")).unwrap();
    controller::grant_event(
        &inner,
        &refresh::WatchGrantsResponse {
            grant: "other-grant".into(),
            version: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let mut values = response("ref", "value");
    cache::record(&inner, &request("ref"), &mut values, &secrets).unwrap();
    assert!(inner.lock().unwrap().secrets["ref"].metadata.is_some());
    // Cross-watch observations still fence value caching for the whole batch.
    assert_eq!(values.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    assert!(inner.lock().unwrap().values.is_empty());
    // Capture the grant after its own stream's event, then let only the other
    // watch advance while its metadata RPC is in flight.
    let grant = inner.observe_grant("grant").unwrap();
    controller::secret_event(
        &inner,
        &store::WatchSecretsResponse {
            reference: "other-ref".into(),
            version: 2,
            ..Default::default()
        },
    )
    .unwrap();
    cache::grant(
        &inner,
        &refresh::GrantStatus {
            grant: "grant".into(),
            version: 1,
            state: "pending".into(),
            ..Default::default()
        },
        &grant,
    )
    .unwrap();
    assert!(inner.lock().unwrap().grants["grant"].metadata.is_some());
}

#[tokio::test]
async fn reconnect_epochs_fence_only_their_own_metadata_but_all_cached_values() {
    let inner = inner();
    let grant = inner.observe_grant("grant").unwrap();
    inner.unknown(ChangeKind::Secrets).unwrap();
    cache::grant(
        &inner,
        &refresh::GrantStatus {
            grant: "grant".into(),
            version: 1,
            state: "pending".into(),
            ..Default::default()
        },
        &grant,
    )
    .unwrap();
    assert!(inner.lock().unwrap().grants["grant"].metadata.is_some());
    inner.ready(ChangeKind::Secrets).unwrap();

    let secret = inner.observe_secrets(&request("ref")).unwrap();
    inner.unknown(ChangeKind::Grants).unwrap();
    let mut values = response("ref", "value");
    cache::record(&inner, &request("ref"), &mut values, &secret).unwrap();
    assert!(inner.lock().unwrap().secrets["ref"].metadata.is_some());
    assert_eq!(values.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    inner.ready(ChangeKind::Grants).unwrap();
    assert!(cache::get(&inner, &request("ref")).unwrap().is_none());
}

#[tokio::test]
async fn late_old_epoch_results_preserve_version_floors_without_restoring_metadata() {
    let inner = inner();
    let mut unpinned = request("ref");
    unpinned.secrets[0].expected_version = None;
    let old_secret = inner.observe_secrets(&unpinned).unwrap();
    let old_grant = inner.observe_grant("grant").unwrap();
    inner.unknown(ChangeKind::Secrets).unwrap();
    inner.unknown(ChangeKind::Grants).unwrap();
    inner.ready(ChangeKind::Secrets).unwrap();
    inner.ready(ChangeKind::Grants).unwrap();
    let current_secret = inner.observe_secrets(&request("ref")).unwrap();
    let current_grant = inner.observe_grant("grant").unwrap();

    // These newer versions are authenticated, but their pre-reset observation
    // tokens do not authorize restoring the post-reset metadata snapshot.
    let mut newer = response("ref", "newer");
    newer.secrets[0].version = 2;
    cache::record(&inner, &unpinned, &mut newer, &old_secret).unwrap();
    let mut status = refresh::GrantStatus {
        grant: "grant".into(),
        version: 2,
        state: "pending".into(),
        ..Default::default()
    };
    cache::grant(&inner, &status, &old_grant).unwrap();
    assert!(inner.lock().unwrap().secrets["ref"].metadata.is_none());
    assert!(inner.lock().unwrap().grants["grant"].metadata.is_none());

    // Requests admitted in the new epoch may still have read the older state
    // before those newer results arrived. Neither may downgrade our knowledge.
    assert_eq!(
        cache::record(
            &inner,
            &request("ref"),
            &mut response("ref", "older"),
            &current_secret,
        )
        .unwrap_err()
        .code(),
        Code::Aborted
    );
    status.version = 1;
    assert_eq!(
        cache::grant(&inner, &status, &current_grant)
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert!(inner.lock().unwrap().values.is_empty());
}

#[tokio::test]
async fn deleted_grant_inspection_fences_inflight_outputs_even_before_first_cache_fill() {
    let inner = inner();
    let secret = inner.observe_secrets(&request("output")).unwrap();
    let grant = inner.observe_grant("grant").unwrap();
    let deleted = refresh::GrantStatus {
        grant: "grant".into(),
        version: 2,
        state: "deleted".into(),
        ..Default::default()
    };
    cache::grant(&inner, &deleted, &grant).unwrap();
    let mut values = response("output", "stale");
    cache::record(&inner, &request("output"), &mut values, &secret).unwrap();
    assert_eq!(values.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    assert!(inner.lock().unwrap().secrets["output"].metadata.is_none());
    assert!(inner.lock().unwrap().values.is_empty());

    // Re-reading a terminal grant is not a new deletion. It must not starve
    // unrelated secret reconciliation by continually changing its epoch.
    let current = inner.observe_secrets(&request("live")).unwrap();
    let grant = inner.observe_grant("grant").unwrap();
    cache::grant(&inner, &deleted, &grant).unwrap();
    cache::record(
        &inner,
        &request("live"),
        &mut response("live", "current"),
        &current,
    )
    .unwrap();
    assert!(cache::get(&inner, &request("live")).unwrap().is_some());
}

#[tokio::test]
async fn terminal_inspection_upgrades_a_provisionally_missing_grant_fence() {
    for terminal in ["deleted", "detached"] {
        let inner = inner();
        let grant = inner.observe_grant("grant").unwrap();
        {
            let mut state = inner.lock().unwrap();
            state.retire_grant("grant", 0);
            state.grants.get_mut("grant").unwrap().terminal = false;
        }
        let secret = inner.observe_secrets(&request("output")).unwrap();
        cache::grant(
            &inner,
            &refresh::GrantStatus {
                grant: "grant".into(),
                version: 2,
                state: terminal.into(),
                ..Default::default()
            },
            &grant,
        )
        .unwrap();
        let mut values = response("output", "value");
        cache::record(&inner, &request("output"), &mut values, &secret).unwrap();
        assert_eq!(
            cache::get(&inner, &request("output")).unwrap().is_some(),
            terminal == "detached"
        );
        inner.unknown(ChangeKind::Grants).unwrap();
        let state = inner.lock().unwrap();
        assert!(state.grants["grant"].gone);
        assert!(state.grants["grant"].terminal);
    }
}
