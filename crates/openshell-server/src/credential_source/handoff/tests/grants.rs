// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
mod pending;
mod postgres;
mod status;
use openshell_core::proto::credentials::refresh::v1 as refresh;
use openshell_credential_issuer::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, RecoveryAction,
    RetrySchedule, StrategyDescriptor, TokenMinter,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[derive(Debug, Default)]
struct Minter {
    calls: AtomicUsize,
    fail: AtomicBool,
    block: AtomicBool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:journal".into(),
            config: vec![MaterialDescriptor {
                name: "audience".into(),
                required: true,
            }],
            secret_material: vec![MaterialDescriptor {
                name: "seed".into(),
                required: true,
            }],
            outputs: vec!["first".into(), "second".into()],
            rotated_secret_material: vec![],
        }
    }
    async fn mint(&self, _: MintRequest) -> Result<MintResponse, MintFailure> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.block.swap(false, Ordering::SeqCst) {
            self.started.notify_one();
            self.release.notified().await;
        }
        if self.fail.load(Ordering::SeqCst) {
            return Err(MintFailure {
                status: Status::failed_precondition("private failure"),
                recovery_action: RecoveryAction::FixConfiguration,
                failure_code: "configuration_invalid",
                provider_error_subtype: None,
                retry_schedule: RetrySchedule::Configuration,
            });
        }
        Ok(MintResponse {
            outputs: HashMap::from([
                ("first".into(), format!("first-{count}")),
                ("second".into(), format!("second-{count}")),
            ]),
            rotated_secret_material: HashMap::new(),
            expiration_time_ms: current_time_ms() + 60_000,
        })
    }
}
fn plan() -> GrantPlan {
    GrantPlan {
        credential_key: "TOKEN".into(),
        strategy: "custom:journal".into(),
        outputs: BTreeMap::from([
            ("first".into(), "TOKEN".into()),
            ("second".into(), "OTHER_TOKEN".into()),
        ]),
        refresh_before_ms: 0,
        max_lifetime_seconds: 120,
    }
}
async fn issuer() -> (Issuer, RemoteProviderSource, Arc<Minter>) {
    let minter = Arc::new(Minter::default());
    let mut registry = MinterRegistry::default();
    registry.register_custom(minter.clone()).unwrap();
    let issuer = Issuer::with_minters(Arc::new(registry)).await;
    let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
    (issuer, source, minter)
}
async fn begin(store: &Store, source: &RemoteProviderSource) -> StaticHandoff {
    StaticHandoff::begin_grant(store, source, &provider(), plan(), None)
        .await
        .unwrap()
}
async fn fill(
    handoff: &mut StaticHandoff,
    store: &Store,
    source: &RemoteProviderSource,
) -> Result<(), Status> {
    handoff
        .fill_grant(
            store,
            source,
            &HashMap::from([("audience".into(), "private-audience".into())]),
            &HashMap::from([("seed".into(), "private-refresh-material".into())]),
        )
        .await
}
async fn ready(store: &Store, source: &RemoteProviderSource) -> StaticHandoff {
    let mut handoff = begin(store, source).await;
    handoff.reserve(store, source).await.unwrap();
    fill(&mut handoff, store, source).await.unwrap();
    handoff
}
async fn published(store: &Store, source: &RemoteProviderSource) -> (StaticHandoff, Provider) {
    let mut handoff = ready(store, source).await;
    let mut provider = provider();
    provider.credential_handles = handoff.handles(source).unwrap();
    handoff
        .publish(store, source, write(&provider))
        .await
        .unwrap();
    (handoff, provider)
}
#[tokio::test]
async fn invalid_or_unregistered_grant_plans_allocate_no_gateway_ownership() {
    let store = test_store().await;
    let (_issuer, source, minter) = issuer().await;
    let mut invalid = plan();
    invalid.outputs.insert("second".into(), "TOKEN".into());
    assert!(
        StaticHandoff::begin_grant(&store, &source, &provider(), invalid, None)
            .await
            .is_err()
    );
    let mut unavailable = plan();
    unavailable.strategy = "custom:absent".into();
    assert!(
        StaticHandoff::begin_grant(&store, &source, &provider(), unavailable, None)
            .await
            .is_err()
    );
    assert!(
        store
            .list_object_page(
                KIND,
                crate::persistence::ObjectListQuery::AllWorkspaces,
                None,
                32
            )
            .await
            .unwrap()
            .records
            .is_empty()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn refresh_before_publication_keeps_stable_bundle_ownership() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let mut handoff = ready(&store, &source).await;
    let handles = handoff.handles(&source).unwrap();
    issuer
        .raw
        .rotate_grant(refresh::RotateGrantRequest {
            grant: handoff.grant_id().unwrap().into(),
            idempotency_key: "before-publication".into(),
        })
        .await
        .unwrap();
    let mut provider = provider();
    provider.credential_handles = handles.clone();
    handoff
        .publish(&store, &source, write(&provider))
        .await
        .unwrap();
    assert_eq!(
        store
            .get_message::<Provider>(provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .credential_handles,
        handles
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
}
#[tokio::test]
async fn grant_handoff_journals_identity_before_values_and_publishes_a_bound_bundle() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let mut handoff = begin(&store, &source).await;
    assert!(handoff.grant_id().is_none());
    handoff.reserve(&store, &source).await.unwrap();
    let id = handoff.grant_id().unwrap().to_owned();
    assert!(
        handoff
            .state
            .slots
            .values()
            .all(|slot| slot.reference.is_some())
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    assert!(
        handoff
            .fill(&store, &source, &HashMap::new(), &HashMap::new())
            .await
            .is_err()
    );
    fill(&mut handoff, &store, &source).await.unwrap();
    let mut provider = provider();
    provider.credential_handles = handoff.handles(&source).unwrap();
    assert!(
        provider.credential_handles.values().all(|handle| source
            .decode(handle)
            .unwrap()
            .grant
            .as_deref()
            == Some(&id))
    );
    handoff
        .publish(&store, &source, write(&provider))
        .await
        .unwrap();
    for row in [
        store.get(KIND, handoff.id()).await.unwrap().unwrap(),
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .unwrap(),
    ] {
        let metadata = String::from_utf8_lossy(&row.payload);
        assert!(!metadata.contains("private-audience"));
        assert!(!metadata.contains("private-refresh-material"));
        assert!(!metadata.contains("first-1"));
    }
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let values = source
        .resolve_provider_handles(&provider, current_time_ms())
        .await
        .unwrap();
    assert_eq!(values.values["TOKEN"], "first-1");
    assert_eq!(values.values["OTHER_TOKEN"], "second-1");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn lost_grant_reservation_response_recovers_identity_and_fences_late_material() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let handoff = begin(&store, &source).await;
    let plan = plan();
    let request = refresh::ReserveGrantRequest {
        owner: Some(handoff.owner(&plan.credential_key)),
        strategy: plan.strategy,
        outputs: plan.outputs.into_iter().collect(),
        refresh_before: Some(openshell_core::time::duration_from_std(Duration::ZERO).unwrap()),
        max_lifetime: Some(
            openshell_core::time::duration_from_std(Duration::from_mins(2)).unwrap(),
        ),
        idempotency_key: handoff
            .operation(&plan.credential_key, "reserve-grant")
            .unwrap(),
    };
    let reserved = issuer.raw.reserve_grant(request.clone()).await.unwrap();
    assert!(handoff.grant_id().is_none());
    let mut recovered = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    recovered.abort(&store, &source).await.unwrap();
    assert!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(issuer.raw.reserve_grant(request).await.unwrap(), reserved);
    assert_eq!(
        issuer
            .raw
            .initialize_grant(refresh::InitializeGrantRequest {
                grant: reserved.grant,
                config: HashMap::from([("audience".into(), "late".into())]),
                secret_material: HashMap::from([("seed".into(), "late".into())]),
                idempotency_key: "late".into()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn failed_mint_can_only_be_abandoned_not_refilled_with_different_material() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let mut handoff = begin(&store, &source).await;
    handoff.reserve(&store, &source).await.unwrap();
    let id = handoff.grant_id().unwrap().to_owned();
    minter.fail.store(true, Ordering::SeqCst);
    assert!(fill(&mut handoff, &store, &source).await.is_err());
    assert_eq!(handoff.state.phase, Phase::Filling);
    assert!(
        handoff
            .fill_grant(&store, &source, &HashMap::new(), &HashMap::new())
            .await
            .is_err()
    );
    let result = StaticHandoff::recover_page(&store, &source, None, 32, i64::MAX)
        .await
        .unwrap();
    assert_eq!(result.cleaned, 1);
    assert!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        issuer
            .raw
            .get_grant(refresh::GetGrantRequest { grant: id })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "deleting"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn cleanup_claim_fences_a_late_known_grant_mint_before_publication() {
    let store = Arc::new(test_store().await);
    let (_issuer, source, minter) = issuer().await;
    let mut handoff = begin(&store, &source).await;
    handoff.reserve(&store, &source).await.unwrap();
    let id = handoff.id().to_owned();
    minter.block.store(true, Ordering::SeqCst);
    let started = minter.started.notified();
    let task_store = store.clone();
    let task_source = source.clone();
    let task = tokio::spawn(async move { fill(&mut handoff, &task_store, &task_source).await });
    started.await;
    let mut cleanup = StaticHandoff::load(&store, &id).await.unwrap().unwrap();
    assert_eq!(cleanup.state.phase, Phase::Filling);
    cleanup.state.phase = Phase::Aborting;
    cleanup.save(&store).await.unwrap();
    minter.release.notify_one();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        tonic::Code::Aborted
    );
    cleanup.abort(&store, &source).await.unwrap();
    assert!(
        store
            .get("provider", provider().object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn provider_deletion_claims_the_entire_grant_before_revoking_its_outputs() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let (handoff, provider) = published(&store, &source).await;
    let grant = handoff.grant_id().unwrap().to_owned();
    StaticHandoff::delete_provider(
        &store,
        &source,
        provider.object_id(),
        1,
        std::slice::from_ref(&handoff),
    )
    .await
    .unwrap();
    let mut retired = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.state.phase, Phase::Aborting);
    retired.abort(&store, &source).await.unwrap();
    assert!(
        StaticHandoff::load(&store, handoff.id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        issuer
            .raw
            .get_grant(refresh::GetGrantRequest { grant })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "deleting"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn metadata_updates_preserve_grants_but_partial_bundle_retirement_rolls_back() {
    let store = test_store().await;
    let (_issuer, source, minter) = issuer().await;
    let (handoff, mut provider) = published(&store, &source).await;
    provider
        .metadata
        .as_mut()
        .unwrap()
        .labels
        .insert("team".into(), "platform".into());
    StaticHandoff::update_preserving(
        &store,
        &source,
        &provider,
        1,
        std::slice::from_ref(&handoff),
    )
    .await
    .unwrap();
    let current = StaticHandoff::load(&store, handoff.id())
        .await
        .unwrap()
        .unwrap();
    provider.credential_handles.remove("TOKEN");
    let error = StaticHandoff::update_preserving(
        &store,
        &source,
        &provider,
        2,
        std::slice::from_ref(&current),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.message(),
        "issuer grant outputs must be retired together"
    );
    assert_eq!(
        store
            .get("provider", provider.object_id())
            .await
            .unwrap()
            .unwrap()
            .resource_version,
        2
    );
    assert_eq!(
        StaticHandoff::load(&store, current.id())
            .await
            .unwrap()
            .unwrap()
            .revision,
        current.revision
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn whole_bundle_replacement_claims_the_old_grant_atomically() {
    let store = test_store().await;
    let (issuer, source, minter) = issuer().await;
    let (old, mut provider) = published(&store, &source).await;
    let old_id = old.grant_id().unwrap().to_owned();
    let mut replacement = StaticHandoff::begin_grant(&store, &source, &provider, plan(), Some(1))
        .await
        .unwrap();
    replacement.reserve(&store, &source).await.unwrap();
    fill(&mut replacement, &store, &source).await.unwrap();
    provider.credential_handles = replacement.handles(&source).unwrap();
    replacement
        .publish_replacing(
            &store,
            &source,
            AtomicWrite::Update {
                object_type: "provider".into(),
                id: provider.object_id().into(),
                payload: provider.encode_to_vec(),
                expected_version: 1,
            },
            std::slice::from_ref(&old),
        )
        .await
        .unwrap();
    let mut retired = StaticHandoff::load(&store, old.id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retired.state.phase, Phase::Aborting);
    retired.abort(&store, &source).await.unwrap();
    assert!(
        StaticHandoff::load(&store, replacement.id())
            .await
            .unwrap()
            .unwrap()
            .is_published()
    );
    assert_eq!(
        issuer
            .raw
            .get_grant(refresh::GetGrantRequest { grant: old_id })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "deleting"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
}
