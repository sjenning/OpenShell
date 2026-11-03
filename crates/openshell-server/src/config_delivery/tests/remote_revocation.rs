// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credential_source::{
    ProviderCredentialSource, RemoteProviderSource, delivery_watch, tests::issuer::Issuer,
};
use openshell_core::proto::{
    ConfigApplyOutcome, ConfigUpdate, ConfigurationAdmissionState, SupervisorMessage,
    credentials::store::v1 as wire, supervisor_message,
};
use std::sync::atomic::Ordering;

mod delivery;

async fn answer(harness: &SupervisorStreamHarness, update: &ConfigUpdate, installed: bool) {
    let mut result = session::applied_result(update);
    if !installed {
        result.outcome = ConfigApplyOutcome::FailedRetainedLastKnownGood.into();
        let admission = result.admission.as_mut().unwrap();
        admission.state = ConfigurationAdmissionState::Rejected.into();
        admission.error = "provider environment is not ready for installation".into();
        result.policy_load = None;
    }
    harness
        .outbound
        .send(SupervisorMessage {
            payload: Some(supervisor_message::Payload::ConfigUpdateResult(result)),
        })
        .await
        .unwrap();
}

async fn admitted(state: &ServerState, revision: u64) {
    observed_admission(state, revision, false).await;
}

/// Failed environment delivery revokes credentials, not the accepted policy.
/// `record_session_admission` therefore retains its accepted revision and
/// records the failure in `error`; recovery must durably clear that error.
async fn observed_admission(state: &ServerState, revision: u64, environment_failed: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let sandbox = state
                .store
                .get_message::<Sandbox>("sandbox")
                .await
                .unwrap()
                .unwrap();
            if sandbox
                .status
                .as_ref()
                .and_then(|status| status.configuration_admission.as_ref())
                .is_some_and(|admission| {
                    admission.provider_env_revision == revision
                        && admission.state == i32::from(ConfigurationAdmissionState::Accepted)
                        && admission.error.is_empty() != environment_failed
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("configuration admission is acknowledged durably");
}

#[tokio::test]
async fn authenticated_issuer_revocation_pushes_static_invalidation_and_recovery() {
    let mut state = push_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "GITHUB_TOKEN".into(),
        provider: "provider".into(),
    };
    let first = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "initial-static-token".into(),
            idempotency_key: "initial-push".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let handles = HashMap::from([(
        "GITHUB_TOKEN".into(),
        source.reference_handle(&first.reference, None).unwrap(),
    )]);
    Arc::get_mut(&mut state).unwrap().provider_source = Some(source.clone());
    put_driver_provider(&state, handles).await;
    let provider = state
        .store
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    put_sandbox(&state, "sandbox", &["provider"]).await;
    change_policy(&state, "sandbox", 1).await;
    let _watch = delivery_watch::spawn(&state, &source);
    let (mut harness, session_id, bootstrap) =
        accepted_session_with_bootstrap(&state, "sandbox").await;
    let bootstrap = bootstrap.unwrap();
    let original = bootstrap.sandbox_config.as_ref().unwrap();
    assert!(original.configuration_admitted);
    let installed = bootstrap.provider_environment.as_ref().unwrap();
    let token = installed
        .values
        .iter()
        .find(|value| value.name == "GITHUB_TOKEN")
        .unwrap();
    assert_eq!(token.value, "initial-static-token");
    assert!(
        token.expiration_time.is_none(),
        "the regression needs a non-expiring installed credential"
    );
    admitted(&state, original.provider_env_revision).await;
    assert!(
        next_update(&mut harness, Duration::from_millis(100))
            .await
            .is_none()
    );
    let stored_before = state
        .store
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    let reads_before = issuer.resolves.load(Ordering::SeqCst);

    // Use the independent authenticated client: the gateway must learn the
    // revocation from its real issuer watch, not a local mutation publication.
    issuer
        .raw
        .delete_secret(wire::DeleteSecretRequest {
            owner: Some(owner.clone()),
            reference: first.reference,
            expected_version: Some(first.version),
            idempotency_key: "revoke-push".into(),
        })
        .await
        .unwrap();
    let invalidation = sent_config(
        &next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("issuer revocation must push an invalidation after the initial ack"),
    );
    let snapshot = invalidation.sandbox_config.as_ref().unwrap();
    let environment = invalidation.provider_environment.as_ref().unwrap();
    assert!(
        snapshot.configuration_admitted,
        "credential availability must not reject the policy"
    );
    assert_eq!(snapshot.policy, original.policy);
    assert_eq!(snapshot.config_revision, original.config_revision);
    assert_ne!(
        snapshot.provider_env_revision,
        original.provider_env_revision
    );
    assert!(names_provider_environment(snapshot, environment));
    assert!(environment.values.is_empty());
    assert!(
        environment.dynamic_credentials.is_empty(),
        "no old dynamic values are replayed"
    );
    assert_eq!(
        environment.readiness_reason,
        i32::from(ProviderReadinessReason::CredentialInstallFailed)
    );
    assert_eq!(
        issuer.resolves.load(Ordering::SeqCst),
        reads_before,
        "invalidation reads no secret values"
    );
    let stored_after = state
        .store
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_after.payload, stored_before.payload);
    assert_eq!(
        stored_after.resource_version,
        stored_before.resource_version
    );
    assert!(
        state
            .supervisor_sessions
            .is_current_session("sandbox", &session_id)
    );
    answer(&harness, &invalidation, false).await;
    observed_admission(&state, original.provider_env_revision, true).await;

    // A revoked reference is terminal. Repair it with a newly authorized
    // reference and confirm recovery on this same live session, not reconnect.
    let replacement = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner),
            value: "replacement-static-token".into(),
            idempotency_key: "repair-push".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut provider = provider;
    provider.credential_handles.insert(
        "GITHUB_TOKEN".into(),
        source
            .reference_handle(&replacement.reference, None)
            .unwrap(),
    );
    source.register_provider(&provider).unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    state.store.put_message(&provider).await.unwrap();
    publish_provider(&state, "default", "provider");
    let recovered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let update = sent_config(
                &next_update(&mut harness, Duration::from_secs(5))
                    .await
                    .expect("recovery update"),
            );
            let environment = update.provider_environment.as_ref().unwrap();
            if environment.readiness_reason
                == i32::from(ProviderReadinessReason::CredentialInstallFailed)
            {
                // A retry may have been built before the repair committed.
                assert_eq!(
                    environment.provider_env_revision,
                    snapshot.provider_env_revision
                );
                answer(&harness, &update, false).await;
                continue;
            }
            break update;
        }
    })
    .await
    .expect("issuer repair resolves the current environment");
    let environment = recovered.provider_environment.as_ref().unwrap();
    assert!(
        environment
            .values
            .iter()
            .any(|value| value.name == "GITHUB_TOKEN" && value.value == "replacement-static-token")
    );
    assert_ne!(
        environment.provider_env_revision,
        snapshot.provider_env_revision
    );
    answer(&harness, &recovered, true).await;
    admitted(&state, environment.provider_env_revision).await;
    assert!(
        state
            .supervisor_sessions
            .is_current_session("sandbox", &session_id)
    );
}

/// Keep issuer authentication and value resolution real, but hold just the
/// metadata projection Unknown to exercise equal-version recovery reliably.
#[derive(Debug)]
struct MetadataGate {
    source: Arc<RemoteProviderSource>,
    unknown: std::sync::atomic::AtomicBool,
    resolves: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl ProviderCredentialSource for MetadataGate {
    async fn project_expiration_metadata(
        &self,
        store: &crate::persistence::Store,
        provider: &mut Provider,
    ) -> Result<(), Status> {
        self.source
            .project_expiration_metadata(store, provider)
            .await
    }

    async fn reference_versions(
        &self,
        store: &crate::persistence::Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        self.source.reference_versions(store, provider).await
    }

    async fn capture_metadata(
        &self,
        store: &crate::persistence::Store,
        provider: &mut Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        if self.unknown.load(Ordering::SeqCst) {
            return Err(Status::unavailable("issuer metadata is unknown"));
        }
        self.source.capture_metadata(store, provider).await
    }

    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        purpose: crate::credential_source::CredentialReadPurpose,
    ) -> Result<crate::credentials::ResolvedProviderCredentials, Status> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        self.source
            .resolve_provider_handles_for(provider, now_ms, purpose)
            .await
    }
}

#[tokio::test]
async fn unknown_metadata_recovery_at_equal_versions_resolves_again() {
    let mut state = push_state().await;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "GITHUB_TOKEN".into(),
        provider: "provider".into(),
    };
    let first = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner),
            value: "same-version-token".into(),
            idempotency_key: "unknown-initial".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    put_driver_provider(
        &state,
        HashMap::from([(
            "GITHUB_TOKEN".into(),
            source.reference_handle(&first.reference, None).unwrap(),
        )]),
    )
    .await;
    source
        .register_provider(
            &state
                .store
                .get_message::<Provider>("provider")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let gate = Arc::new(MetadataGate {
        source,
        unknown: std::sync::atomic::AtomicBool::new(false),
        resolves: std::sync::atomic::AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().provider_source = Some(gate.clone());
    put_sandbox(&state, "sandbox", &["provider"]).await;
    change_policy(&state, "sandbox", 1).await;
    let (mut harness, _, bootstrap) = accepted_session_with_bootstrap(&state, "sandbox").await;
    let original = bootstrap.unwrap();
    let original_revision = original
        .sandbox_config
        .as_ref()
        .unwrap()
        .provider_env_revision;
    admitted(&state, original_revision).await;
    let before = gate.resolves.load(Ordering::SeqCst);
    assert!(before > 0);
    gate.unknown.store(true, Ordering::SeqCst);
    publish_all_local(&state);
    let invalidation = sent_config(
        &next_update(&mut harness, Duration::from_secs(5))
            .await
            .expect("unknown metadata invalidates installed credentials"),
    );
    let invalidation_revision = invalidation
        .sandbox_config
        .as_ref()
        .unwrap()
        .provider_env_revision;
    assert_ne!(invalidation_revision, original_revision);
    assert_eq!(gate.resolves.load(Ordering::SeqCst), before);
    answer(&harness, &invalidation, false).await;
    observed_admission(&state, original_revision, true).await;
    gate.unknown.store(false, Ordering::SeqCst);
    publish_all_local(&state);
    let recovery = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let update = sent_config(
                &next_update(&mut harness, Duration::from_secs(5))
                    .await
                    .expect("equal-version recovery"),
            );
            if update
                .provider_environment
                .as_ref()
                .unwrap()
                .readiness_reason
                == i32::from(ProviderReadinessReason::CredentialInstallFailed)
            {
                assert_eq!(
                    update
                        .sandbox_config
                        .as_ref()
                        .unwrap()
                        .provider_env_revision,
                    invalidation_revision
                );
                answer(&harness, &update, false).await;
                continue;
            }
            break update;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        recovery
            .sandbox_config
            .as_ref()
            .unwrap()
            .provider_env_revision,
        original_revision
    );
    assert_eq!(recovery.provider_environment, original.provider_environment);
    assert!(
        gate.resolves.load(Ordering::SeqCst) > before,
        "recovery must not reuse the gateway's cached values"
    );
    answer(&harness, &recovery, true).await;
    admitted(&state, original_revision).await;
}

#[tokio::test]
async fn configuration_store_failure_does_not_invalidate_cached_credentials() {
    let state = push_state().await;
    let (mut harness, record) = driver_backed_session(&state).await;
    let before = record.provider_environment().unwrap();
    // This failure occurs before the credential metadata boundary. It must
    // remain a retry, not turn a storage outage into an environment update.
    state.store.close().await;
    let (failed, _) = Builder(&state).deliver(&record).await;
    assert!(failed);
    assert_eq!(record.provider_environment(), Some(before.clone()));
    // Closing the store may close the live session while its bootstrap ack
    // is being persisted. A timeout, clean EOF, or transport error is fine;
    // none may be mistaken for a configuration invalidation.
    let _ = tokio::time::timeout(Duration::from_millis(100), async {
        while let Ok(Some(message)) = harness.inbound.message().await {
            assert!(
                !is_config_update(&message),
                "a configuration-store outage must not publish credential invalidation"
            );
        }
    })
    .await;
    assert_eq!(record.provider_environment(), Some(before));
}
