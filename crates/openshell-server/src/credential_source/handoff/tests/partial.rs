// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
mod postgres;

use super::*;
use std::sync::atomic::Ordering;

#[test]
fn older_journal_slots_do_not_gain_retirement_authority() {
    let slot: Slot =
        serde_json::from_str(r#"{"reference":"opaque-reference","filled":true}"#).unwrap();
    assert!(!slot.retiring);
}
async fn two_keys(store: &Store, source: &RemoteProviderSource) -> (StaticHandoff, Provider) {
    let mut original = provider();
    let mut journal = StaticHandoff::begin(
        store,
        source,
        &original,
        &["FIRST".into(), "SECOND".into()],
        None,
    )
    .await
    .unwrap();
    journal.reserve(store, source).await.unwrap();
    journal
        .fill(
            store,
            source,
            &HashMap::from([
                ("FIRST".into(), "first-original".into()),
                ("SECOND".into(), "second-untouched".into()),
            ]),
            &HashMap::new(),
        )
        .await
        .unwrap();
    original.credential_handles = journal.handles(source).unwrap();
    journal
        .publish(store, source, write(&original))
        .await
        .unwrap();
    (journal, original)
}
async fn metadata(
    issuer: &Issuer,
    journal: &StaticHandoff,
    key: &str,
) -> Result<wire::ResolveSecretsResponse, Status> {
    issuer
        .raw
        .resolve_secrets(wire::ResolveSecretsRequest {
            purpose: wire::ResolvePurpose::MetadataInspection as i32,
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "metadata".into(),
                owner: Some(journal.owner(key)),
                reference: journal.state.slots[key].reference.clone().unwrap(),
                expected_version: None,
            }],
        })
        .await
}
#[tokio::test]
async fn partial_replacement_and_key_removal_never_read_or_revoke_untouched_credentials() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, mut provider) = two_keys(&store, &source).await;
    let second = provider.credential_handles["SECOND"].clone();
    let mut new = StaticHandoff::begin(&store, &source, &provider, &["FIRST".into()], Some(1))
        .await
        .unwrap();
    new.reserve(&store, &source).await.unwrap();
    new.fill(
        &store,
        &source,
        &HashMap::from([("FIRST".into(), "first-replaced".into())]),
        &HashMap::new(),
    )
    .await
    .unwrap();
    provider
        .credential_handles
        .extend(new.handles(&source).unwrap());
    new.publish_replacing(
        &store,
        &source,
        AtomicWrite::Update {
            object_type: "provider".into(),
            id: provider.object_id().into(),
            expected_version: 1,
            payload: provider.encode_to_vec(),
        },
        std::slice::from_ref(&old),
    )
    .await
    .unwrap();
    let mut cleanup = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    assert!(cleanup.is_published());
    assert!(cleanup.state.slots["FIRST"].retiring);
    assert!(!cleanup.state.slots["SECOND"].retiring);
    cleanup.cleanup_retired(&store, &source).await.unwrap();
    assert!(metadata(&issuer, &old, "FIRST").await.is_err());
    assert!(metadata(&issuer, &old, "SECOND").await.is_ok());
    assert!(metadata(&issuer, &new, "FIRST").await.is_ok());
    assert_eq!(provider.credential_handles["SECOND"], second);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let owned = StaticHandoff::published_for_provider(&store, &source, &provider)
        .await
        .unwrap();
    provider.credential_handles.remove("SECOND");
    StaticHandoff::update_preserving(&store, &source, &provider, 2, &owned)
        .await
        .unwrap();
    let result = StaticHandoff::recover_page(&store, &source, None, 128, i64::MIN)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert!(metadata(&issuer, &old, "SECOND").await.is_err());
    assert!(metadata(&issuer, &new, "FIRST").await.is_ok());
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn metadata_only_updates_preserve_all_keys_and_reject_reference_injection() {
    let store = test_store().await;
    let issuer = Issuer::start().await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    let (old, mut provider) = two_keys(&store, &source).await;
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    provider.config.insert("option".into(), "changed".into());
    provider
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("team".into(), "one".into());
    StaticHandoff::update_preserving(&store, &source, &provider, 1, std::slice::from_ref(&old))
        .await
        .unwrap();
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    let owned = StaticHandoff::published_for_provider(&store, &source, &provider)
        .await
        .unwrap();
    assert!(owned[0].state.slots.values().all(|slot| !slot.retiring));
    let mut changed_expiration = provider.clone();
    changed_expiration.credential_expiration_times.insert(
        "FIRST".into(),
        openshell_core::time::timestamp_from_millis(current_time_ms() + 60_000).unwrap(),
    );
    assert!(
        StaticHandoff::update_preserving(&store, &source, &changed_expiration, 2, &owned)
            .await
            .is_err()
    );
    let mut injected = provider.clone();
    injected.credential_handles.insert(
        "THIRD".into(),
        provider.credential_handles["SECOND"].clone(),
    );
    assert!(
        StaticHandoff::update_preserving(&store, &source, &injected, 2, &owned)
            .await
            .is_err()
    );
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles,
        provider.credential_handles
    );
}
