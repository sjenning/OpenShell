// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

// Aborting tonic's accept loop alone leaves established HTTP/2 connections
// alive. This forwarding proxy owns every connection task, so aborting it is a
// deterministic transport outage rather than an assumption about fixture Drop.
async fn outage_proxy(
    state: &mut Arc<ServerState>,
    issuer: &Issuer,
) -> tokio::task::JoinHandle<()> {
    let endpoint = reqwest::Url::parse(&issuer.startup.endpoint).unwrap();
    let upstream = format!("127.0.0.1:{}", endpoint.port().unwrap())
        .parse()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut downstream, _) = accepted.unwrap();
                    openshell_core::net::set_tcp_nodelay_best_effort(&downstream);
                    connections.spawn(async move {
                        let mut upstream = openshell_core::net::connect_tcp_nodelay_best_effort(&[upstream]).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    let mut config = issuer.startup.clone();
    config.endpoint = format!("https://localhost:{}", address.port());
    let source: Arc<dyn crate::credential_source::ProviderCredentialSource> =
        Arc::new(config.connect(&state.store).await.unwrap());
    let state = Arc::get_mut(state).unwrap();
    state.provider_source = Some(source.clone());
    state.provider_profile_sources = state
        .provider_profile_sources
        .clone()
        .with_strategy_source(source);
    proxy
}

#[tokio::test]
async fn unchanged_validated_profiles_reuse_catalog_evidence_during_issuer_outage() {
    let (_directory, mut state, issuer, _minter, _provider) =
        context(profiles::multi_descriptor()).await;
    let proxy = outage_proxy(&mut state, &issuer).await;
    profiles::update_profile(&state, profiles::declared_profile(&state).await).await;
    let before = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    assert!(
        before
            .get_type_profile("company-profile")
            .unwrap()
            .allows_runtime_provider_credentials()
    );
    proxy.abort();
    let _ = proxy.await;
    let after = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state
            .provider_profile_sources
            .snapshot_catalog(&state.store, "default"),
    )
    .await
    .expect("an unchanged profile catalog must not call the unavailable issuer")
    .unwrap();
    assert_eq!(before.revision(), after.revision());
    assert!(
        after
            .get_type_profile("company-profile")
            .unwrap()
            .allows_runtime_provider_credentials()
    );
    // A different source snapshot cannot borrow the old registration evidence.
    // Write directly to model an external/interceptor profile change while the
    // issuer is unavailable; public profile mutations already validate live.
    let mut stored = state
        .store
        .get_message_by_name::<StoredProviderProfile>("default", "company-profile")
        .await
        .unwrap()
        .unwrap();
    stored.profile.as_mut().unwrap().display_name = "Changed while offline".into();
    state.store.put_message(&stored).await.unwrap();
    let changed = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state
            .provider_profile_sources
            .snapshot_catalog(&state.store, "default"),
    )
    .await;
    assert!(
        !matches!(changed, Ok(Ok(_))),
        "a changed profile must not inherit cached catalog authorization"
    );
}

#[tokio::test]
async fn selecting_another_issuer_does_not_reuse_profile_catalog_registration_evidence() {
    let (_directory, mut state, _issuer, _minter, _provider) =
        context(profiles::multi_descriptor()).await;
    profiles::update_profile(&state, profiles::declared_profile(&state).await).await;
    state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    let empty = Issuer::start().await;
    let source: Arc<dyn crate::credential_source::ProviderCredentialSource> =
        Arc::new(RemoteProviderSource::new("replacement", empty.watched.clone()).unwrap());
    let state_mut = Arc::get_mut(&mut state).unwrap();
    state_mut.provider_source = Some(source.clone());
    state_mut.provider_profile_sources = state_mut
        .provider_profile_sources
        .clone()
        .with_strategy_source(source);
    let error = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert!(error.message().contains("selected issuer catalog"));
}
