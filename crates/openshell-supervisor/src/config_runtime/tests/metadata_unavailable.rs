// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime consumers of metadata-unavailable polling and reconnect delivery.
//! The gateway producer tests cover deriving the distinct failed identity.

use super::*;
use openshell_core::grpc_client::{ProviderEnvironmentResult, SettingsPollResult};
use openshell_core::proto::{
    ConfigurationAdmissionState, PolicySource, ProviderEnvironmentSnapshot,
    ProviderEnvironmentValue, ProviderEnvironmentValueClassification, ProviderProfileCredential,
};

fn healthy_settings() -> SettingsPollResult {
    let mut settings = settings_poll_result(Some(proto_policy_fixture()), 1, PolicySource::Sandbox);
    settings.provider_env_revision = 6;
    settings.provider_attachment_epoch = "epoch-a".into();
    settings
        .settings
        .insert("ocsf_json_enabled".into(), effective_bool(true));
    settings
}

fn environment_for(settings: &SettingsPollResult, token: &str) -> ProviderEnvironmentResult {
    let mut provider = static_provider_environment(settings.provider_env_revision, Some(token));
    provider.policy_hash.clone_from(&settings.policy_hash);
    provider
        .provider_attachment_epoch
        .clone_from(&settings.provider_attachment_epoch);
    provider
        .dynamic_credentials
        .insert("dynamic".into(), ProviderProfileCredential::default());
    assert!(provider.credential_expires_at_ms.is_empty());
    provider
}

fn install_startup_token(ctx: &mut PolicyPollLoopContext, settings: &SettingsPollResult) -> String {
    ctx.provider_credentials = initial_provider_credentials(
        environment_for(settings, "old-static-token"),
        &ctx.provider_readiness,
    );
    let reference = ctx.provider_credentials.snapshot().child_env["EXTERNAL_TOKEN"].clone();
    assert_token(&ctx.provider_credentials, &reference, "old-static-token");
    reference
}

fn assert_token(state: &ProviderCredentialState, reference: &str, token: &str) {
    assert_eq!(state.snapshot().child_env["EXTERNAL_TOKEN"], reference);
    assert_eq!(
        state
            .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
            .expect("endpoint-bound resolver installed")
            .resolve_placeholder(reference),
        Some(token),
    );
}

fn assert_revoked(state: &ProviderCredentialState) {
    assert!(!state.snapshot().child_env.contains_key("EXTERNAL_TOKEN"));
    assert!(state.resolver().is_none());
    assert!(
        state
            .resolver_for_endpoint("tools.example.com", 443, "/v1/chat")
            .is_none()
    );
    assert_eq!(
        state.snapshot().dynamic_credentials.get("dynamic"),
        Some(&ProviderProfileCredential::default()),
        "failed static refresh must preserve the independently installed dynamic selector"
    );
}

#[tokio::test]
async fn polling_metadata_failure_revokes_until_fresh_equal_version_recovery() {
    let healthy = healthy_settings();
    let engine = Arc::new(OpaEngine::from_proto(&proto_policy_fixture()).unwrap());
    let generation = engine.current_generation();
    let guard = engine.generation_guard(generation).unwrap();
    let mut ctx = policy_poll_test_context(
        engine.clone(),
        LoadedPolicyOrigin::Gateway {
            revision: Some(LoadedPolicyRevision::from_snapshot(&healthy)),
            has_last_valid_policy: true,
        },
        default_middleware_connector(),
    );
    let reference = install_startup_token(&mut ctx, &healthy);
    let state = ctx.provider_credentials.clone();
    let readiness = ctx.provider_readiness.clone();
    let ocsf_enabled = ctx.ocsf_enabled.clone();
    let (policy, polls, mut reports) = scripted_policy_gateway();
    let (requests, mut received) = tokio::sync::mpsc::unbounded_channel();
    polls.send(healthy.clone()).unwrap();
    let task = tokio::spawn(run_policy_poll_loop_with_client(
        ctx,
        ScriptedProviderGateway { policy, requests },
    ));
    expect_policy_report(&mut reports, healthy.version).await;

    // External metadata failure changes only the provider identity. Authored
    // policy, attachment epoch, settings, and their versions remain valid.
    let mut unavailable = healthy.clone();
    unavailable.provider_env_revision = 99;
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::NotFound,
        tonic::Code::Aborted,
    ] {
        let installed = state.snapshot().installation_id.clone();
        polls.send(unavailable.clone()).unwrap();
        let (_, response) = timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("failed metadata identity must request the environment again")
            .expect("poll loop active");
        assert!(
            response
                .send(Err(openshell_core::grpc_client::grpc_status_error(
                    tonic::Status::new(code, "selected credential metadata unavailable"),
                )))
                .is_ok()
        );
        timeout(Duration::from_secs(5), async {
            while state.revision() != unavailable.provider_env_revision
                || state.snapshot().installation_id == installed
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("each failed fetch must complete static revocation");
        assert_revoked(&state);
        assert!(!readiness.observation(&state).credentials_installed);
        assert_eq!(engine.current_generation(), generation);
        assert!(!guard.is_stale());
        assert!(engine.fail_closed_reason().is_none());
        assert!(ocsf_enabled.load(Ordering::Relaxed));
    }

    // No authored/provider version advances on repair. Fetch again even though
    // this is the original healthy fingerprint, not a newer revision.
    polls.send(healthy.clone()).unwrap();
    let (_, response) = timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("original healthy versions must trigger a fresh fetch")
        .expect("poll loop active");
    assert_revoked(&state);
    assert!(
        response
            .send(Ok(environment_for(&healthy, "fresh-static-token")))
            .is_ok()
    );
    timeout(Duration::from_secs(5), async {
        while state.revision() != healthy.provider_env_revision
            || !readiness.observation(&state).credentials_installed
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("equal-version recovery installs the freshly fetched credentials");
    assert_token(&state, &reference, "fresh-static-token");
    assert!(readiness.observation(&state).policy_active);
    assert_eq!(
        readiness.observation(&state).config_revision,
        healthy.config_revision
    );
    assert!(engine.fail_closed_reason().is_none());
    task.abort();
    let _ = task.await;
}

fn delivered_environment(
    settings: &SettingsPollResult,
    token: &str,
) -> ProviderEnvironmentSnapshot {
    let mut provider = environment_for(settings, token);
    ProviderEnvironmentSnapshot {
        provider_env_revision: provider.provider_env_revision,
        provider_attachment_epoch: provider.provider_attachment_epoch,
        policy_hash: provider.policy_hash,
        dynamic_credentials: provider.dynamic_credentials,
        values: vec![ProviderEnvironmentValue {
            name: "EXTERNAL_TOKEN".into(),
            value: token.into(),
            classification: ProviderEnvironmentValueClassification::StaticCredential.into(),
            static_credential_binding: provider.static_credential_bindings.remove("EXTERNAL_TOKEN"),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn update_with_environment(
    id: &str,
    settings: &SettingsPollResult,
    provider: ProviderEnvironmentSnapshot,
) -> openshell_core::proto::ConfigUpdate {
    let mut update = config_update(id, settings);
    let sandbox = update.sandbox_config.as_mut().unwrap();
    sandbox.settings.clone_from(&settings.settings);
    sandbox.settings_revision = settings.settings_revision;
    update.provider_environment = Some(provider);
    update
}

#[tokio::test]
async fn unresolved_reconnect_bootstrap_revokes_and_equal_version_delivery_recovers() {
    let healthy = healthy_settings();
    let (mut ctx, config_apply_tx, _push_tx) = push_session_poll_loop(&healthy);
    let reference = install_startup_token(&mut ctx, &healthy);
    let state = ctx.provider_credentials.clone();
    let readiness = ctx.provider_readiness.clone();
    let ocsf_enabled = ctx.ocsf_enabled.clone();
    let engine = ctx.opa_engine.clone();
    let generation = engine.current_generation();
    let guard = engine.generation_guard(generation).unwrap();
    let (session_tx, session_rx) = tokio::sync::watch::channel(Some("session-1".to_string()));
    ctx.supervisor_session_id = session_rx;
    let (client, polls, mut reports) = scripted_policy_gateway();
    let poll_calls = client.poll_calls.clone();
    polls.send(healthy.clone()).unwrap();
    let task = tokio::spawn(run_policy_poll_loop_with_client(ctx, client));
    expect_policy_report(&mut reports, healthy.version).await;

    session_tx.send_replace(None);
    let mut unavailable = healthy.clone();
    unavailable.provider_env_revision = 99;
    let unresolved = ProviderEnvironmentSnapshot {
        provider_env_revision: unavailable.provider_env_revision,
        provider_attachment_epoch: unavailable.provider_attachment_epoch.clone(),
        policy_hash: unavailable.policy_hash.clone(),
        readiness_reason: ProviderReadinessReason::CredentialInstallFailed.into(),
        ..Default::default()
    };
    session_tx.send_replace(Some("session-2".to_string()));
    let result = deliver_update(
        &config_apply_tx,
        update_with_environment("unresolved-reconnect-bootstrap", &unavailable, unresolved),
    )
    .await;
    assert_eq!(
        result.outcome,
        i32::from(ConfigApplyOutcome::FailedRetainedLastKnownGood)
    );
    assert_eq!(
        result.failure.unwrap().code,
        "provider_environment_unavailable"
    );
    assert_eq!(result.policy_load, None);
    assert_revoked(&state);
    assert_eq!(state.revision(), unavailable.provider_env_revision);
    assert!(!readiness.observation(&state).credentials_installed);
    assert_eq!(engine.current_generation(), generation);
    assert!(!guard.is_stale());
    assert!(engine.fail_closed_reason().is_none());
    assert!(ocsf_enabled.load(Ordering::Relaxed));

    let result = deliver_update(
        &config_apply_tx,
        update_with_environment(
            "equal-version-repair",
            &healthy,
            delivered_environment(&healthy, "fresh-static-token"),
        ),
    )
    .await;
    assert_eq!(result.outcome, i32::from(ConfigApplyOutcome::Applied));
    assert_eq!(
        result.admission.unwrap().state,
        i32::from(ConfigurationAdmissionState::Accepted)
    );
    assert_eq!(result.policy_load, None);
    assert_eq!(state.revision(), healthy.provider_env_revision);
    assert_token(&state, &reference, "fresh-static-token");
    assert!(readiness.observation(&state).credentials_installed);
    assert!(readiness.observation(&state).policy_active);
    assert_eq!(
        readiness.observation(&state).config_revision,
        healthy.config_revision
    );
    assert!(engine.fail_closed_reason().is_none());
    assert_eq!(poll_calls.load(Ordering::SeqCst), 1);
    expect_no_policy_report(&mut reports).await;
    task.abort();
    let _ = task.await;
}
