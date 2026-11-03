// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn owner() -> store::SecretOwner {
    request("ref").secrets.remove(0).owner.unwrap()
}
fn revoke(inner: &Inner, reference: &str) {
    controller::secret_event(
        inner,
        &store::WatchSecretsResponse {
            reference: reference.into(),
            version: 2,
            revoked: true,
            ..Default::default()
        },
    )
    .unwrap();
}
fn retire(inner: &Inner, grant: &str) {
    controller::grant_event(
        inner,
        &refresh::WatchGrantsResponse {
            grant: grant.into(),
            version: 2,
            deleted: true,
            ..Default::default()
        },
    )
    .unwrap();
}
#[tokio::test]
async fn deleted_reference_and_grant_churn_reuses_capacity_without_evicting_active_bindings() {
    let inner = inner();
    inner.track_secret(owner(), "active-ref".into()).unwrap();
    inner.track_grant("active-grant".into()).unwrap();
    for number in 0..REFERENCES * 2 {
        let reference = format!("ref-{number}");
        inner.track_secret(owner(), reference.clone()).unwrap();
        revoke(&inner, &reference);
        // Watch resets must not turn terminal bindings into active capacity.
        if number % 100 == 0 {
            inner.unknown(ChangeKind::Secrets).unwrap();
        }
    }
    for number in 0..GRANTS * 2 {
        let grant = format!("grant-{number}");
        inner.track_grant(grant.clone()).unwrap();
        retire(&inner, &grant);
        if number % 100 == 0 {
            inner.unknown(ChangeKind::Grants).unwrap();
        }
    }
    let state = inner.lock().unwrap();
    assert!(state.secrets.len() <= REFERENCES);
    assert!(state.grants.len() <= GRANTS);
    assert!(!state.secrets["active-ref"].gone);
    assert!(!state.grants["active-grant"].gone);
}
#[tokio::test]
async fn allocation_admission_reserves_the_whole_bundle_and_releases_on_cancellation() {
    let inner = Arc::new(inner());
    for number in 0..REFERENCES - 2 {
        inner
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
    for number in 0..GRANTS - 1 {
        inner.track_grant(format!("active-{number}")).unwrap();
    }
    let admission = inner.admit(2, 1).unwrap();
    assert_eq!(
        inner
            .track_secret(owner(), "competitor".into())
            .unwrap_err()
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        inner.track_grant("competitor".into()).unwrap_err().code(),
        Code::ResourceExhausted
    );
    drop(admission);
    assert_eq!(inner.lock().unwrap().reserved_secrets, 0);
    assert_eq!(inner.lock().unwrap().reserved_grants, 0);
    inner
        .admit(2, 1)
        .unwrap()
        .commit(
            vec![("one".into(), owner()), ("two".into(), owner())],
            vec!["grant".into()],
        )
        .unwrap();
    let state = inner.lock().unwrap();
    assert_eq!(state.secrets.len(), REFERENCES);
    assert_eq!(state.grants.len(), GRANTS);
    assert!(state.secrets.contains_key("one") && state.secrets.contains_key("two"));
}
#[tokio::test]
async fn rejected_bundle_does_not_publish_partial_reference_or_grant_tracking() {
    let inner = Arc::new(inner());
    inner.track_secret(owner(), "existing".into()).unwrap();
    let mut wrong_owner = owner();
    wrong_owner.provider_id = "other".into();
    let admission = inner.admit(2, 1).unwrap();
    assert_eq!(
        admission
            .commit(
                vec![("new".into(), owner()), ("existing".into(), wrong_owner)],
                vec!["new-grant".into()]
            )
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let state = inner.lock().unwrap();
    assert!(!state.secrets.contains_key("new"));
    assert!(!state.grants.contains_key("new-grant"));
    assert_eq!(state.reserved_secrets, 0);
    assert_eq!(state.reserved_grants, 0);
}
#[tokio::test]
async fn reclaimed_binding_cannot_be_restored_by_inflight_values_or_metadata() {
    let inner = inner();
    let before = inner.observe_secrets(&request("old")).unwrap();
    {
        let mut state = inner.lock().unwrap();
        state.retire_secret("old", 0);
        state.secrets.get_mut("old").unwrap().terminal = false;
    }
    // Force reclamation while the old RPC still holds its binding token.
    for number in 0..REFERENCES {
        inner
            .track_secret(owner(), format!("active-{number}"))
            .unwrap();
    }
    assert!(!inner.lock().unwrap().secrets.contains_key("old"));
    {
        let mut state = inner.lock().unwrap();
        state.retire_secret("active-0", 0);
        state.secrets.get_mut("active-0").unwrap().terminal = false;
    }
    inner.track_secret(owner(), "old".into()).unwrap();
    assert!(!inner.lock().unwrap().secrets["old"].gone);
    let mut late = response("old", "stale");
    assert_eq!(
        cache::record(&inner, &request("old"), &mut late, &before)
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    let mut inspection = request("old");
    inspection.purpose = store::ResolvePurpose::MetadataInspection as i32;
    assert_eq!(
        cache::record(&inner, &inspection, &mut response("old", ""), &before)
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert!(inner.lock().unwrap().secrets["old"].metadata.is_none());
    assert!(inner.lock().unwrap().values.is_empty());
    // A newly authenticated read can recover an actively re-registered binding.
    let current = inner.observe_secrets(&request("old")).unwrap();
    cache::record(
        &inner,
        &request("old"),
        &mut response("old", "current"),
        &current,
    )
    .unwrap();
    assert_eq!(
        cache::get(&inner, &request("old"))
            .unwrap()
            .unwrap()
            .secrets[0]
            .value,
        "current"
    );
}
#[tokio::test]
async fn late_grant_inspection_cannot_restore_reclaimed_terminal_tracking() {
    let inner = inner();
    let before = inner.observe_grant("old").unwrap();
    {
        let mut state = inner.lock().unwrap();
        state.retire_grant("old", 0);
        state.grants.get_mut("old").unwrap().terminal = false;
    }
    for number in 0..GRANTS {
        inner.track_grant(format!("active-{number}")).unwrap();
    }
    {
        let mut state = inner.lock().unwrap();
        state.retire_grant("active-0", 0);
        state.grants.get_mut("active-0").unwrap().terminal = false;
    }
    let current = inner.observe_grant("old").unwrap();
    let status = refresh::GrantStatus {
        grant: "old".into(),
        state: "pending".into(),
        version: 1,
        ..Default::default()
    };
    assert_eq!(
        cache::grant(&inner, &status, &before).unwrap_err().code(),
        Code::Aborted
    );
    assert!(inner.lock().unwrap().grants["old"].metadata.is_none());
    cache::grant(&inner, &status, &current).unwrap();
    assert_eq!(
        inner.lock().unwrap().grants["old"]
            .metadata
            .as_ref()
            .unwrap()
            .state,
        "pending"
    );
}
#[tokio::test]
async fn terminal_status_reclaims_grants_without_retiring_detached_outputs() {
    let inner = inner();
    inner.track_secret(owner(), "published".into()).unwrap();
    for number in 0..GRANTS * 2 {
        let grant = format!("grant-{number}");
        let before = inner.observe_grant(&grant).unwrap();
        cache::grant(
            &inner,
            &refresh::GrantStatus {
                grant,
                state: if number % 2 == 0 {
                    "detached"
                } else {
                    "deleted"
                }
                .into(),
                version: 1,
                ..Default::default()
            },
            &before,
        )
        .unwrap();
    }
    let state = inner.lock().unwrap();
    assert!(state.grants.len() <= GRANTS);
    assert!(state.grants.values().all(|entry| entry.gone));
    assert!(!state.secrets["published"].gone);
}
#[tokio::test]
async fn metadata_returned_after_mutation_invalidation_remains_unknown() {
    let inner = inner();
    let before = inner.observe_secrets(&request("ref")).unwrap();
    let grant_before = inner.observe_grant("grant").unwrap();
    inner
        .mutation_status(inner.observe_grant("grant").unwrap(), None, true)
        .unwrap();
    let mut request = request("ref");
    request.purpose = store::ResolvePurpose::MetadataInspection as i32;
    cache::record(&inner, &request, &mut response("ref", ""), &before).unwrap();
    cache::grant(
        &inner,
        &refresh::GrantStatus {
            grant: "grant".into(),
            version: 1,
            state: "pending".into(),
            ..Default::default()
        },
        &grant_before,
    )
    .unwrap();
    let state = inner.lock().unwrap();
    assert!(state.secrets["ref"].metadata.is_none());
    assert!(state.grants["grant"].metadata.is_none());
}

#[tokio::test]
async fn missing_bindings_are_reclaimed_without_consuming_a_lifetime_quota() {
    let inner = inner();
    inner.track_secret(owner(), "live".into()).unwrap();
    inner.track_grant("live".into()).unwrap();
    for number in 0..REFERENCES * 2 {
        let id = format!("missing-{number}");
        inner.track_secret(owner(), id.clone()).unwrap();
        let mut state = inner.lock().unwrap();
        state.retire_secret(&id, 0);
        state.secrets.get_mut(&id).unwrap().terminal = false;
    }
    for number in 0..GRANTS * 2 {
        let id = format!("missing-{number}");
        inner.track_grant(id.clone()).unwrap();
        let mut state = inner.lock().unwrap();
        state.retire_grant(&id, 0);
        state.grants.get_mut(&id).unwrap().terminal = false;
    }
    let state = inner.lock().unwrap();
    assert!(state.secrets.len() <= REFERENCES);
    assert!(state.grants.len() <= GRANTS);
    assert!(!state.secrets["live"].gone);
    assert!(!state.grants["live"].gone);
}

#[tokio::test]
async fn logically_deleted_grants_reclaim_capacity_even_when_physical_cleanup_stalls() {
    let inner = inner();
    inner.track_grant("live".into()).unwrap();
    inner.track_secret(owner(), "published".into()).unwrap();
    for number in 0..GRANTS * 2 {
        let id = format!("deleting-{number}");
        let before = inner.observe_grant(&id).unwrap();
        cache::grant(
            &inner,
            &refresh::GrantStatus {
                grant: id.clone(),
                version: 2,
                state: "deleting".into(),
                ..Default::default()
            },
            &before,
        )
        .unwrap();
        assert!(inner.lock().unwrap().grants[&id].gone);
    }
    let state = inner.lock().unwrap();
    assert!(state.grants.len() <= GRANTS);
    assert!(!state.grants["live"].gone);
    assert!(!state.secrets["published"].gone);
}
