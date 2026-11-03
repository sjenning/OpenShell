// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::credential_source::{
    ProviderCredentialSource as _, RemoteProviderSource, tests::issuer::Issuer,
};
use openshell_core::proto::credentials::{refresh::v1 as refresh_wire, store::v1 as store_wire};
use openshell_credential_issuer::minter::{
    MintFailure, MintRequest, MintResponse, MinterRegistry, StrategyDescriptor, TokenMinter,
};
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Debug, Default)]
struct Minter(AtomicUsize);
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:export".into(),
            config: vec![],
            secret_material: vec![],
            outputs: vec!["access_token".into()],
            rotated_secret_material: vec![],
        }
    }
    async fn mint(&self, _: MintRequest) -> Result<MintResponse, MintFailure> {
        let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(MintResponse {
            outputs: HashMap::from([("access_token".into(), format!("native-access-{count}"))]),
            expiration_time_ms: crate::persistence::current_time_ms() + 3_600_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}
async fn native() -> (
    Arc<ServerState>,
    Provider,
    Issuer,
    Arc<RemoteProviderSource>,
    Arc<Minter>,
) {
    let (mut state, mut provider) = fixture().await;
    provider.metadata.as_mut().unwrap().id = uuid::Uuid::new_v4().to_string();
    provider.metadata.as_mut().unwrap().workspace = "default".into();
    provider.credentials.clear();
    let minter = Arc::new(Minter::default());
    let mut registry = MinterRegistry::default();
    registry.register_custom(minter.clone()).unwrap();
    let issuer = Issuer::with_minters(Arc::new(registry)).await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    let provider_id = provider.object_id().to_string();
    let owner = |key: &str| store_wire::SecretOwner {
        workspace: "default".into(),
        provider_id: provider_id.clone(),
        credential_key: key.into(),
        provider: "provider".into(),
    };
    let grant = issuer
        .raw
        .create_grant(refresh_wire::CreateGrantRequest {
            owner: Some(owner("ACCESS_TOKEN")),
            strategy: "custom:export".into(),
            outputs: HashMap::from([("access_token".into(), "ACCESS_TOKEN".into())]),
            idempotency_key: "grant".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    provider.credential_handles.insert(
        "ACCESS_TOKEN".into(),
        source
            .reference_handle(&grant.output_references["access_token"], Some(&grant.grant))
            .unwrap(),
    );
    let secret = issuer
        .raw
        .put_secret(store_wire::PutSecretRequest {
            owner: Some(owner("STATIC_KEY")),
            value: "native-static-secret".into(),
            idempotency_key: "static".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    provider.credential_handles.insert(
        "STATIC_KEY".into(),
        source.reference_handle(&secret.reference, None).unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    state.store.put_message(&provider).await.unwrap();
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    (state, provider, issuer, source, minter)
}
fn selected(keys: &[&str]) -> Request<GetProviderCredentialsRequest> {
    let mut value = request(keys);
    value.workspace_scope = Some(workspace_selector("default"));
    authenticated(value)
}
#[tokio::test]
async fn remote_export_prevalidates_the_whole_selection_then_uses_issuer_freshness_once() {
    let (state, _, _issuer, _source, minter) = native().await;
    assert!(
        handle(&state, selected(&["ACCESS_TOKEN", "UNDECLARED"]))
            .await
            .is_err()
    );
    assert_eq!(minter.0.load(Ordering::SeqCst), 0);
    let first = handle(&state, selected(&["ACCESS_TOKEN"]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first.credentials["ACCESS_TOKEN"].value, "native-access-1");
    let second = handle(&state, selected(&["ACCESS_TOKEN"]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(second.credentials["ACCESS_TOKEN"].value, "native-access-1");
    assert_eq!(minter.0.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn operator_export_cannot_use_a_delivery_cached_value_or_an_inline_fallback() {
    let (state, mut provider, issuer, source, minter) = native().await;
    provider
        .credential_handles
        .retain(|key, _| key == "STATIC_KEY");
    source
        .resolve_provider_handles(&provider, crate::persistence::current_time_ms())
        .await
        .unwrap();
    let before = issuer.resolves.load(Ordering::SeqCst);
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    assert_eq!(
        handle(&state, selected(&["STATIC_KEY"]))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), before + 1);
    assert_eq!(minter.0.load(Ordering::SeqCst), 0);
    issuer.fail_resolves.store(false, Ordering::SeqCst);
    assert_eq!(
        handle(&state, selected(&["STATIC_KEY"]))
            .await
            .unwrap()
            .into_inner()
            .credentials["STATIC_KEY"]
            .value,
        "native-static-secret"
    );
    provider
        .credentials
        .insert("STATIC_KEY".into(), "forbidden-inline-fallback".into());
    state.store.put_message(&provider).await.unwrap();
    assert_eq!(
        handle(&state, selected(&["STATIC_KEY"]))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
}
#[tokio::test]
async fn every_grant_is_validated_before_any_selected_grant_is_minted() {
    let (state, mut provider, _issuer, source, minter) = native().await;
    let binding: serde_json::Value =
        serde_json::from_str(&provider.credential_handles["STATIC_KEY"].handle).unwrap();
    provider.credential_handles.insert(
        "STATIC_KEY".into(),
        source
            .reference_handle(
                binding["reference"].as_str().unwrap(),
                Some("zzzz-missing-grant"),
            )
            .unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    assert!(
        handle(&state, selected(&["ACCESS_TOKEN", "STATIC_KEY"]))
            .await
            .is_err()
    );
    assert_eq!(minter.0.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn whole_batch_immutable_owner_validation_precedes_freshness_and_value_reads() {
    let (state, mut provider, issuer, source, minter) = native().await;
    let foreign = issuer
        .raw
        .put_secret(store_wire::PutSecretRequest {
            owner: Some(store_wire::SecretOwner {
                workspace: "default".into(),
                provider_id: "foreign-provider".into(),
                credential_key: "STATIC_KEY".into(),
                provider: String::new(),
            }),
            value: "must-not-export".into(),
            idempotency_key: "foreign".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    provider.credential_handles.insert(
        "STATIC_KEY".into(),
        source.reference_handle(&foreign.reference, None).unwrap(),
    );
    state.store.put_message(&provider).await.unwrap();
    let before = issuer.resolves.load(Ordering::SeqCst);
    assert!(
        handle(&state, selected(&["ACCESS_TOKEN", "STATIC_KEY"]))
            .await
            .is_err()
    );
    assert_eq!(minter.0.load(Ordering::SeqCst), 0);
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), before);
}
