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
    controlled_proxy(state, issuer, None).await
}

#[derive(Default)]
struct StalledRequests {
    enabled: std::sync::atomic::AtomicBool,
    received: tokio::sync::Notify,
}

async fn controlled_proxy(
    state: &mut Arc<ServerState>,
    issuer: &Issuer,
    stalled: Option<Arc<StalledRequests>>,
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
                    let stalled = stalled.clone();
                    connections.spawn(async move {
                        let mut upstream = openshell_core::net::connect_tcp_nodelay_best_effort(&[upstream]).await.unwrap();
                        if let Some(stalled) = stalled {
                            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                            let (mut reader, mut writer) = downstream.split();
                            let (mut upstream_reader, mut upstream_writer) = upstream.split();
                            let requests = async {
                                let mut buffer = [0u8; 8192];
                                loop {
                                    let count = reader.read(&mut buffer).await?;
                                    if count == 0 {
                                        return Ok::<_, std::io::Error>(());
                                    }
                                    if stalled.enabled.load(Ordering::SeqCst) {
                                        stalled.received.notify_one();
                                        std::future::pending::<()>().await;
                                    }
                                    upstream_writer.write_all(&buffer[..count]).await?;
                                }
                            };
                            let responses = tokio::io::copy(&mut upstream_reader, &mut writer);
                            let _ = tokio::try_join!(requests, responses);
                        } else {
                            let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                        }
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
async fn stalled_uncached_workspace_does_not_block_cached_policy_and_settings() {
    let (_directory, mut state, issuer, _minter, _provider) =
        context(profiles::multi_descriptor()).await;
    let stalled = Arc::new(StalledRequests::default());
    let proxy = controlled_proxy(&mut state, &issuer, Some(stalled.clone())).await;
    profiles::update_profile(&state, profiles::declared_profile(&state).await).await;
    let catalog = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "default")
        .await
        .unwrap();
    let mut other = crate::provider_profile_sources::stored_provider_profile(
        catalog.get_profile("company-profile").unwrap(),
    );
    other.metadata.as_mut().unwrap().workspace = "uncached-workspace".into();
    other.profile.as_mut().unwrap().display_name = "Uncached workspace".into();
    state.store.put_message(&other).await.unwrap();
    let sandbox = Sandbox {
        metadata: Some(meta("cached-policy-consumer")),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    let before = policy::build_sandbox_config_snapshot(&state, &sandbox)
        .await
        .unwrap();
    stalled.enabled.store(true, Ordering::SeqCst);
    let miss_state = state.clone();
    let miss = tokio::spawn(async move {
        miss_state
            .provider_profile_sources
            .snapshot_catalog(&miss_state.store, "uncached-workspace")
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stalled.received.notified(),
    )
    .await
    .expect("the uncached request must reach the stalled issuer transport");
    assert!(!miss.is_finished(), "the cache miss must still be stalled");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        policy::build_sandbox_config_snapshot(&state, &sandbox),
    )
    .await;
    let still_stalled = !miss.is_finished();
    miss.abort();
    let _ = miss.await;
    proxy.abort();
    let _ = proxy.await;
    let after = result
        .expect("cached policy/settings must not wait for another workspace's RPC")
        .unwrap();
    assert!(still_stalled);
    assert_eq!(before.policy, after.policy);
    assert_eq!(before.settings, after.settings);
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
    // A distinct authored workspace catalog must not evict default's evidence.
    let mut other = crate::provider_profile_sources::stored_provider_profile(
        before.get_profile("company-profile").unwrap(),
    );
    other.metadata.as_mut().unwrap().workspace = "other-workspace".into();
    other.profile.as_mut().unwrap().display_name = "Other workspace".into();
    state.store.put_message(&other).await.unwrap();
    let other_before = state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "other-workspace")
        .await
        .unwrap();
    assert_ne!(before.revision(), other_before.revision());
    let sandbox = Sandbox {
        metadata: Some(meta("offline-catalog-consumer")),
        spec: Some(SandboxSpec {
            policy: Some(SandboxPolicy {
                version: 1,
                ..Default::default()
            }),
            // Policy/settings reads must not need credential values.
            ..Default::default()
        }),
        ..Default::default()
    };
    state.store.put_message(&sandbox).await.unwrap();
    let config_before = policy::build_sandbox_config_snapshot(&state, &sandbox)
        .await
        .unwrap();
    // Alternate once more so the outage starts after a different workspace read.
    state
        .provider_profile_sources
        .snapshot_catalog(&state.store, "other-workspace")
        .await
        .unwrap();
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
    let other_after = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state
            .provider_profile_sources
            .snapshot_catalog(&state.store, "other-workspace"),
    )
    .await
    .expect("both workspace catalogs retain evidence")
    .unwrap();
    assert_eq!(other_before.revision(), other_after.revision());
    let config_after = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        policy::build_sandbox_config_snapshot(&state, &sandbox),
    )
    .await
    .expect("policy/settings delivery must not call the unavailable issuer")
    .unwrap();
    assert_eq!(config_before.policy, config_after.policy);
    assert_eq!(config_before.settings, config_after.settings);
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
