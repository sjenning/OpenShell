// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

fn restarted(fixture: &Fixture) -> RemoteProviderSource {
    RemoteProviderSource::new("primary", WatchedIssuer::new(fixture.issuer.raw.clone()))
        .unwrap()
        .with_gateway_store(fixture.store.clone())
}

fn fill_tracking(source: &RemoteProviderSource, existing: usize) {
    // The original client's two live streams hold the shared transport watch
    // permits. These synthetic active registrations cannot be reconciled away
    // while a fresh client exercises mutation admission at the exact bound.
    for number in existing..4096 {
        source
            .client
            .track_secret(
                owner(identity(), SSH_KEY).unwrap(),
                format!("active-{number}"),
            )
            .unwrap();
    }
}

#[tokio::test]
async fn restarted_cleanup_uses_known_reference_at_full_tracking_capacity() {
    let fixture = Fixture::new().await;
    let handles = fixture.stage("full-known").await;
    fixture
        .candidate("full-known", &handles, identity().id)
        .await;
    let late_publication = fixture.publication("full-known", &handles).await;
    fixture
        .issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let restarted = restarted(&fixture);
    let reference = restarted.decode(&handles[SSH_KEY]).unwrap().reference;
    restarted
        .register_internal(identity(), SSH_KEY, &handles[SSH_KEY])
        .unwrap();
    fill_tracking(&restarted, 1);
    let key = intent::reservation_key(identity(), "full-known", SSH_KEY).unwrap();
    assert_eq!(
        restarted
            .client
            .reserve_secret(wire::ReserveSecretRequest {
                owner: Some(owner(identity(), SSH_KEY).unwrap()),
                idempotency_key: format!("internal-reserve:{key}"),
            })
            .await
            .unwrap_err()
            .code(),
        Code::ResourceExhausted,
        "a fresh client has no observed reservation receipt to replay at capacity"
    );
    let page = restarted
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!((page.cleaned, page.failures, page.conflicts), (1, 0, 0));
    assert!(
        fixture
            .store
            .write_atomically(&late_publication)
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handles[SSH_KEY])
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let row = fixture.journal().await;
    let payload = String::from_utf8(row.payload).unwrap();
    assert!(payload.contains("\"phase\":\"closed\""));
    assert!(!payload.contains(&reference));
}

#[tokio::test]
async fn unknown_ack_at_capacity_retains_closing_ownership_until_discovery_can_retry() {
    let fixture = Fixture::new().await;
    let values = HashMap::from([(SSH_KEY.into(), "private-host-key".into())]);
    let mut pending = intent::Intent::begin(&fixture.source, identity(), "unknown-full", &values)
        .await
        .unwrap();
    let key = intent::reservation_key(identity(), "unknown-full", SSH_KEY).unwrap();
    let reserved = fixture
        .issuer
        .raw
        .reserve_secret(wire::ReserveSecretRequest {
            owner: Some(owner(identity(), SSH_KEY).unwrap()),
            idempotency_key: format!("internal-reserve:{key}"),
        })
        .await
        .unwrap();
    fixture
        .issuer
        .watched
        .wait_synchronized(std::time::Duration::from_secs(5))
        .await
        .unwrap();
    let full = restarted(&fixture);
    fill_tracking(&full, 0);
    let page = full
        .recover_internal_page(None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!((page.cleaned, page.failures), (0, 1));
    let row = fixture.journal().await;
    let payload: serde_json::Value = serde_json::from_slice(&row.payload).unwrap();
    assert_eq!(payload["phase"], "closing");
    assert!(payload["references"][SSH_KEY].is_null());
    assert_eq!(
        pending
            .bind(SSH_KEY, &reserved.reference)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    // With room to discover the lost acknowledgement, retry immediately; the
    // persisted Closing claim does not wait for another idle timeout.
    let retry = restarted(&fixture);
    let page = retry.recover_internal_page(None, 32, 0).await.unwrap();
    assert_eq!((page.cleaned, page.failures), (1, 0));
    let handle = retry.reference_handle(&reserved.reference, None).unwrap();
    assert_eq!(
        fixture
            .value(identity(), SSH_KEY, &handle)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
}
