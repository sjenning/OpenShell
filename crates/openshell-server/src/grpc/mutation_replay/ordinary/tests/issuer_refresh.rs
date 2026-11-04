// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    credential_source::{
        RemoteProviderSource,
        handoff::{GrantPlan, StaticHandoff},
        tests::issuer::Issuer,
    },
    persistence::AtomicWrite,
};
use openshell_credential_issuer::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, StrategyDescriptor,
    TokenMinter,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[derive(Debug, Default)]
struct Minter {
    calls: AtomicUsize,
    block: AtomicBool,
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:rotation".into(),
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
        Ok(MintResponse {
            outputs: HashMap::from([
                ("first".into(), format!("private-token-{count}")),
                ("second".into(), "private-secondary-token".into()),
            ]),
            rotated_secret_material: HashMap::new(),
            expiration_time_ms: crate::persistence::current_time_ms() + 60_000,
        })
    }
}
async fn context() -> (
    tempfile::TempDir,
    Arc<ServerState>,
    Issuer,
    Arc<Minter>,
    Provider,
    StaticHandoff,
) {
    let (directory, mut state) = protected_state().await;
    let minter = Arc::new(Minter::default());
    let mut registry = MinterRegistry::default();
    registry.register_custom(minter.clone()).unwrap();
    let issuer = Issuer::with_minters(Arc::new(registry)).await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    let mut provider = Provider {
        metadata: Some(meta("rotating")),
        r#type: "custom".into(),
        ..Default::default()
    };
    let mut handoff = StaticHandoff::begin_grant(
        &state.store,
        &source,
        &provider,
        GrantPlan {
            credential_key: "TOKEN".into(),
            strategy: "custom:rotation".into(),
            outputs: BTreeMap::from([
                ("first".into(), "TOKEN".into()),
                ("second".into(), "OTHER_TOKEN".into()),
            ]),
            refresh_before_ms: 0,
            max_lifetime_seconds: 120,
        },
        None,
    )
    .await
    .unwrap();
    handoff.reserve(&state.store, &source).await.unwrap();
    handoff
        .prepare_grant(
            &state.store,
            &source,
            &HashMap::from([("audience".into(), "private-configuration".into())]),
            &HashMap::from([("seed".into(), "private-material".into())]),
        )
        .await
        .unwrap();
    provider.credential_handles = handoff.handles(&source).unwrap();
    handoff
        .publish(
            &state.store,
            &source,
            AtomicWrite::Create {
                object_type: "provider".into(),
                id: provider.object_id().into(),
                name: "rotating".into(),
                workspace: "default".into(),
                payload: provider.encode_to_vec(),
            },
        )
        .await
        .unwrap();
    (directory, state, issuer, minter, provider, handoff)
}
fn rotate(key: &str) -> RotateProviderCredentialRequest {
    RotateProviderCredentialRequest {
        provider: "rotating".into(),
        credential_key: key.into(),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    }
}
#[tokio::test]
async fn remote_rotation_replays_metadata_without_values_provider_rewrites_or_a_second_mint() {
    let (_directory, state, issuer, minter, provider, handoff) = context().await;
    let before = state
        .store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    let req = rotate("TOKEN");
    let result = run(&state, authed_request(req.clone()))
        .await
        .unwrap()
        .into_inner();
    let status = result.status.as_ref().unwrap();
    assert_eq!(status.status, "refreshed");
    assert_eq!(status.strategy_name, "custom:rotation");
    assert!(status.expiration_time.is_some());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    let reads = issuer.resolves.load(Ordering::SeqCst);
    assert_eq!(replay(&state, req.clone()).await, result);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), reads);
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    let after = state
        .store
        .get("provider", provider.object_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.payload, before.payload);
    assert_eq!(after.resource_version, before.resource_version);
    for row in state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap()
    {
        let receipt = String::from_utf8(row.payload).unwrap();
        for secret in [
            "private-configuration",
            "private-material",
            "private-token-1",
            "private-secondary-token",
        ] {
            assert!(!receipt.contains(secret));
        }
    }
    let source = state.remote_provider_mutations().unwrap().unwrap();
    StaticHandoff::delete_provider(
        &state.store,
        source,
        provider.object_id(),
        1,
        std::slice::from_ref(&handoff),
    )
    .await
    .unwrap();
    assert_eq!(
        reason(&run(&state, authed_request(req)).await.unwrap_err()),
        "REQUEST_REPLAY_UNAVAILABLE"
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn remote_rotation_validates_primary_key_and_authorization_before_minting() {
    let (_directory, mut state, _issuer, minter, _provider, _handoff) = context().await;
    assert_eq!(
        run(&state, authed_request(rotate("OTHER_TOKEN")))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    Arc::get_mut(&mut state).unwrap().admin_role = "openshell-admin".into();
    assert!(
        run(&state, non_member_request(rotate("TOKEN")))
            .await
            .is_err()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn canceled_remote_rotation_finishes_admitted_work_and_replays_without_reminting() {
    let (_directory, state, _issuer, minter, _provider, _handoff) = context().await;
    minter.block.store(true, Ordering::SeqCst);
    let req = rotate("TOKEN");
    let caller = tokio::spawn({
        let state = state.clone();
        let req = req.clone();
        async move { run(&state, authed_request(req)).await }
    });
    minter.started.notified().await;
    caller.abort();
    let _ = caller.await;
    minter.release.notify_one();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match run(&state, authed_request(req.clone())).await {
                Ok(response) => break response,
                Err(error) => {
                    assert_eq!(reason(&error), "REQUEST_OUTCOME_UNCERTAIN");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(result.into_inner().status.unwrap().status, "refreshed");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn incomplete_remote_bundle_never_authorizes_rotation() {
    let (_directory, state, _issuer, minter, mut provider, _handoff) = context().await;
    provider.credential_handles.remove("OTHER_TOKEN");
    state.store.put_message(&provider).await.unwrap();
    assert!(run(&state, authed_request(rotate("TOKEN"))).await.is_err());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn issuer_metadata_ownership_is_checked_before_a_forged_gateway_binding_can_mint() {
    use openshell_core::proto::credentials::{refresh::v1 as wire, store::v1::SecretOwner};
    let (_directory, mut state, issuer, minter, mut provider, handoff) = context().await;
    let reserved = issuer
        .raw
        .reserve_grant(wire::ReserveGrantRequest {
            owner: Some(SecretOwner {
                workspace: "default".into(),
                provider_id: id(),
                credential_key: "TOKEN".into(),
                provider: "other-provider".into(),
                ..Default::default()
            }),
            strategy: "custom:rotation".into(),
            outputs: HashMap::from([
                ("first".into(), "TOKEN".into()),
                ("second".into(), "OTHER_TOKEN".into()),
            ]),
            refresh_before: None,
            max_lifetime: None,
            idempotency_key: id(),
        })
        .await
        .unwrap();
    issuer
        .raw
        .initialize_grant(wire::InitializeGrantRequest {
            grant: reserved.grant.clone(),
            config: HashMap::from([("audience".into(), "other-configuration".into())]),
            secret_material: HashMap::from([("seed".into(), "other-material".into())]),
            idempotency_key: id(),
        })
        .await
        .unwrap();
    let source = Arc::new(
        RemoteProviderSource::new(
            "primary",
            openshell_credential_issuer::remote_issuer::WatchedIssuer::new(issuer.raw.clone()),
        )
        .unwrap(),
    );
    for (output, key) in [("first", "TOKEN"), ("second", "OTHER_TOKEN")] {
        provider.credential_handles.insert(
            key.into(),
            source
                .reference_handle(&reserved.output_references[output], Some(&reserved.grant))
                .unwrap(),
        );
    }
    state.store.put_message(&provider).await.unwrap();
    let row = state
        .store
        .get("credential_issuer_handoff_v1", handoff.id())
        .await
        .unwrap()
        .unwrap();
    let mut data: serde_json::Value = serde_json::from_slice(&row.payload).unwrap();
    data["grant"]["id"] = reserved.grant.clone().into();
    for (output, key) in [("first", "TOKEN"), ("second", "OTHER_TOKEN")] {
        data["slots"][key]["reference"] = reserved.output_references[output].clone().into();
    }
    state
        .store
        .write_atomically(&[AtomicWrite::Update {
            object_type: "credential_issuer_handoff_v1".into(),
            id: handoff.id().into(),
            payload: serde_json::to_vec(&data).unwrap(),
            expected_version: row.resource_version,
        }])
        .await
        .unwrap();
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source);
    assert!(run(&state, authed_request(rotate("TOKEN"))).await.is_err());
    assert_eq!(minter.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        issuer
            .raw
            .get_grant(wire::GetGrantRequest {
                grant: reserved.grant
            })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "pending"
    );
}
#[tokio::test]
async fn remote_refresh_recipe_uses_a_scalar_allowlist_and_rejects_unclassified_diagnostics() {
    let (_directory, state, _issuer, _minter, provider, handoff) = context().await;
    let binding = handoff.published_grant(&provider).unwrap();
    let mut status = openshell_core::proto::ProviderCredentialRefreshStatus {
        provider_id: binding.provider_id.clone(),
        credential_key: binding.credential_key.clone(),
        strategy_name: binding.strategy_name.clone(),
        status: "configured".into(),
        last_error: "private-upstream-response".into(),
        ..Default::default()
    };
    let recipe = IssuerRefresh::capture(binding.clone(), &status).unwrap();
    assert!(
        !serde_json::to_string(&recipe)
            .unwrap()
            .contains("private-upstream-response")
    );
    // Old receipts omit history. New ones preserve admitted metadata without
    // reading current issuer state or storing free-form upstream diagnostics.
    let legacy: IssuerRefresh =
        serde_json::from_str(&serde_json::to_string(&recipe).unwrap()).unwrap();
    assert!(
        legacy
            .restore(&state.store)
            .await
            .unwrap()
            .last_refresh_time
            .is_none()
    );
    status.last_refresh_time = Some(openshell_core::time::timestamp_from_millis(1234).unwrap());
    status.last_error_time = Some(openshell_core::time::timestamp_from_millis(2345).unwrap());
    status.failure_code = "oauth_invalid_grant".into();
    status.provider_error_subtype = "invalid_rapt".into();
    let recipe = IssuerRefresh::capture(binding.clone(), &status).unwrap();
    let encoded = serde_json::to_string(&recipe).unwrap();
    assert!(!encoded.contains("private-upstream-response"));
    let restored = recipe.restore(&state.store).await.unwrap();
    assert_eq!(restored.last_refresh_time, status.last_refresh_time);
    assert_eq!(restored.last_error_time, status.last_error_time);
    assert_eq!(restored.provider_error_subtype, "invalid_rapt");
    assert_ne!(restored.last_error, status.last_error);
    status.provider_error_subtype = "unclassified-private-subtype".into();
    assert!(IssuerRefresh::capture(binding.clone(), &status).is_err());
    status.provider_error_subtype.clear();
    status.failure_code = "unclassified private diagnostics".into();
    assert!(IssuerRefresh::capture(binding.clone(), &status).is_err());
    status.failure_code.clear();
    status.status = "private_upstream_response".into();
    assert!(IssuerRefresh::capture(binding, &status).is_err());
}
