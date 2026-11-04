// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::auth::principal::{Principal, SandboxIdentitySource, SandboxPrincipal};
use crate::grpc::policy::{
    build_provider_environment_snapshot_from_inputs, load_sandbox_config_inputs,
    load_sandbox_config_inputs_for_delivery,
};
use openshell_core::proto::open_shell_server::OpenShell;
use openshell_core::proto::{
    GetSandboxConfigRequest, GetSandboxConfigResponse, GetSandboxProviderEnvironmentRequest,
};

struct Fixture {
    state: Arc<ServerState>,
    issuer: Issuer,
    gate: Arc<MetadataGate>,
    owner: wire::SecretOwner,
    secret: wire::PutSecretResponse,
}

async fn fixture(mode: ConfigDeliveryMode) -> Fixture {
    let mut state = push_state().await;
    Arc::get_mut(&mut state)
        .unwrap()
        .config
        .config_delivery_mode = mode;
    let issuer = Issuer::start().await;
    let source = Arc::new(RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap());
    let owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "GITHUB_TOKEN".into(),
        provider: "provider".into(),
        ..Default::default()
    };
    let secret = issuer
        .raw
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "initial-nonexpiring-token".into(),
            idempotency_key: "delivery-initial".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    put_driver_provider(
        &state,
        HashMap::from([(
            "GITHUB_TOKEN".into(),
            source.reference_handle(&secret.reference, None).unwrap(),
        )]),
    )
    .await;
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
    let gate = Arc::new(MetadataGate {
        source,
        unknown: std::sync::atomic::AtomicBool::new(false),
        resolves: std::sync::atomic::AtomicUsize::new(0),
    });
    Arc::get_mut(&mut state).unwrap().provider_source = Some(gate.clone());
    put_sandbox(&state, "sandbox", &["provider"]).await;
    change_policy(&state, "sandbox", 1).await;
    Fixture {
        state,
        issuer,
        gate,
        owner,
        secret,
    }
}

fn sandbox_request<T>(message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .extensions_mut()
        .insert(Principal::Sandbox(SandboxPrincipal {
            sandbox_id: "sandbox".into(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".into(),
                auth_epoch: None,
            },
            trust_domain: Some("openshell".into()),
        }));
    request
}

async fn poll(state: &Arc<ServerState>) -> GetSandboxConfigResponse {
    crate::OpenShellService::new(state.clone())
        .get_sandbox_config(sandbox_request(GetSandboxConfigRequest {
            name: "sandbox".into(),
            ..Default::default()
        }))
        .await
        .expect("metadata unavailability must not fail the policy/settings poll")
        .into_inner()
}

async fn fetch(
    state: &Arc<ServerState>,
) -> Result<openshell_core::proto::GetSandboxProviderEnvironmentResponse, Status> {
    crate::OpenShellService::new(state.clone())
        .get_sandbox_provider_environment(sandbox_request(GetSandboxProviderEnvironmentRequest {
            sandbox_id: "sandbox".into(),
            supports_static_credential_bindings: true,
            supports_stable_placeholder_environment_keys: true,
        }))
        .await
        .map(Response::into_inner)
}

async fn revoke(fixture: &Fixture) {
    fixture
        .issuer
        .raw
        .delete_secret(wire::DeleteSecretRequest {
            owner: Some(fixture.owner.clone()),
            reference: fixture.secret.reference.clone(),
            expected_version: Some(fixture.secret.version),
            idempotency_key: "delivery-revoke".into(),
        })
        .await
        .unwrap();
    let provider = fixture
        .state
        .store
        .get_message::<Provider>("provider")
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match fixture
                .gate
                .source
                .capture_metadata(&fixture.state.store, &mut provider.clone())
                .await
            {
                Err(error) if error.code() == Code::NotFound => break,
                Ok(_) => {}
                Err(error) => assert_eq!(error.code(), Code::Unavailable),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the authenticated watch observes revocation");
}

#[tokio::test]
async fn polling_remote_revocation_delivers_changed_identity_without_resolving_values() {
    let fixture = fixture(ConfigDeliveryMode::Poll).await;
    let original = poll(&fixture.state).await;
    let environment = fetch(&fixture.state).await.unwrap();
    assert_eq!(
        environment.provider_env_revision,
        original.provider_env_revision
    );
    assert_eq!(
        environment.environment["GITHUB_TOKEN"],
        "initial-nonexpiring-token"
    );
    assert!(
        !environment
            .credential_expiration_times
            .contains_key("GITHUB_TOKEN")
    );
    let before = fixture
        .state
        .store
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    let resolutions = fixture.gate.resolves.load(Ordering::SeqCst);
    revoke(&fixture).await;

    let failed = poll(&fixture.state).await;
    assert!(
        failed.configuration_admitted,
        "credential failure must not reject valid policy"
    );
    assert_eq!(failed.policy, original.policy);
    assert_eq!(failed.config_revision, original.config_revision);
    assert_eq!(failed.settings, original.settings);
    assert_ne!(failed.provider_env_revision, original.provider_env_revision);
    assert_eq!(
        poll(&fixture.state).await.provider_env_revision,
        failed.provider_env_revision,
        "an unchanged outage has a stable identity"
    );
    assert_eq!(
        fetch(&fixture.state).await.unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(fixture.gate.resolves.load(Ordering::SeqCst), resolutions);
    let after = fixture
        .state
        .store
        .get("provider", "provider")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.resource_version, after.resource_version);
}

#[tokio::test]
async fn polling_unknown_metadata_recovers_at_equal_versions_and_never_resolves_partial_inputs() {
    let fixture = fixture(ConfigDeliveryMode::Poll).await;
    let original = poll(&fixture.state).await;
    fetch(&fixture.state).await.unwrap();
    let resolutions = fixture.gate.resolves.load(Ordering::SeqCst);
    fixture.gate.unknown.store(true, Ordering::SeqCst);
    let failed = poll(&fixture.state).await;
    assert_ne!(failed.provider_env_revision, original.provider_env_revision);
    let sandbox = fixture
        .state
        .store
        .get_message::<Sandbox>("sandbox")
        .await
        .unwrap()
        .unwrap();
    assert!(
        load_sandbox_config_inputs(&fixture.state, sandbox.clone())
            .await
            .is_err(),
        "strict callers must still fail closed"
    );
    let inputs = load_sandbox_config_inputs_for_delivery(&fixture.state, sandbox)
        .await
        .unwrap();
    assert_eq!(
        build_provider_environment_snapshot_from_inputs(&fixture.state, &inputs, true, true)
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    assert_eq!(fixture.gate.resolves.load(Ordering::SeqCst), resolutions);

    fixture.gate.unknown.store(false, Ordering::SeqCst);
    assert_eq!(poll(&fixture.state).await, original);
    let recovered = fetch(&fixture.state).await.unwrap();
    assert_eq!(
        recovered.provider_env_revision,
        original.provider_env_revision
    );
    assert!(
        fixture.gate.resolves.load(Ordering::SeqCst) > resolutions,
        "recovery resolves through the selected source again"
    );
}

#[tokio::test]
async fn reconnect_after_remote_revocation_accepts_an_unresolved_bootstrap() {
    let fixture = fixture(ConfigDeliveryMode::Push).await;
    let (harness, old_session, bootstrap) =
        accepted_session_with_bootstrap(&fixture.state, "sandbox").await;
    let original = bootstrap.unwrap().sandbox_config.unwrap();
    admitted(&fixture.state, original.provider_env_revision).await;
    fixture.state.supervisor_sessions.disconnect("sandbox");
    drop(harness);
    revoke(&fixture).await;
    let resolutions = fixture.gate.resolves.load(Ordering::SeqCst);

    let mut reconnected =
        reconnect_supervisor_stream(&fixture.state, "sandbox", StreamFeatures::Apply)
            .await
            .expect("metadata revocation cannot refuse reconnect before invalidation");
    let message = next_update(&mut reconnected, Duration::from_secs(5))
        .await
        .unwrap();
    let Some(gateway_message::Payload::SessionAccepted(accepted)) = message.payload else {
        panic!("expected accepted reconnect")
    };
    assert_ne!(accepted.session_id, old_session);
    let bootstrap = accepted.bootstrap.unwrap();
    let snapshot = bootstrap.sandbox_config.as_ref().unwrap();
    assert!(snapshot.configuration_admitted);
    assert_eq!(snapshot.policy, original.policy);
    assert_eq!(snapshot.config_revision, original.config_revision);
    assert_ne!(
        snapshot.provider_env_revision,
        original.provider_env_revision
    );
    assert_eq!(
        bootstrap.provider_environment.as_ref().unwrap(),
        &unresolved_provider_environment(snapshot)
    );
    let record = registered_record(&fixture.state, "sandbox", &accepted.session_id).await;
    assert!(
        record.provider_environment().is_none(),
        "the failed bootstrap cannot seed a value cache"
    );
    assert_eq!(fixture.gate.resolves.load(Ordering::SeqCst), resolutions);
    answer(&reconnected, &bootstrap, false).await;
}

#[tokio::test]
async fn reconnect_with_unknown_metadata_recovers_original_versions_on_the_same_session() {
    let fixture = fixture(ConfigDeliveryMode::Push).await;
    let (harness, _, bootstrap) = accepted_session_with_bootstrap(&fixture.state, "sandbox").await;
    let original = bootstrap.unwrap();
    let original_revision = original
        .sandbox_config
        .as_ref()
        .unwrap()
        .provider_env_revision;
    admitted(&fixture.state, original_revision).await;
    fixture.state.supervisor_sessions.disconnect("sandbox");
    drop(harness);
    fixture.gate.unknown.store(true, Ordering::SeqCst);
    let resolutions = fixture.gate.resolves.load(Ordering::SeqCst);
    let mut reconnected =
        reconnect_supervisor_stream(&fixture.state, "sandbox", StreamFeatures::Apply)
            .await
            .unwrap();
    let message = next_update(&mut reconnected, Duration::from_secs(5))
        .await
        .unwrap();
    let Some(gateway_message::Payload::SessionAccepted(accepted)) = message.payload else {
        panic!("expected accepted reconnect")
    };
    let bootstrap = accepted.bootstrap.unwrap();
    let record = registered_record(&fixture.state, "sandbox", &accepted.session_id).await;
    assert!(record.provider_environment().is_none());
    assert_eq!(fixture.gate.resolves.load(Ordering::SeqCst), resolutions);
    assert!(
        bootstrap
            .provider_environment
            .as_ref()
            .unwrap()
            .values
            .is_empty()
    );
    assert_ne!(
        bootstrap
            .sandbox_config
            .as_ref()
            .unwrap()
            .provider_env_revision,
        original_revision
    );
    answer(&reconnected, &bootstrap, false).await;

    fixture.gate.unknown.store(false, Ordering::SeqCst);
    publish_all_local(&fixture.state);
    let recovery = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let update = sent_config(
                &next_update(&mut reconnected, Duration::from_secs(5))
                    .await
                    .expect("recovery update"),
            );
            if update
                .provider_environment
                .as_ref()
                .unwrap()
                .readiness_reason
                == i32::from(ProviderReadinessReason::CredentialInstallFailed)
            {
                answer(&reconnected, &update, false).await;
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
    assert!(fixture.gate.resolves.load(Ordering::SeqCst) > resolutions);
    answer(&reconnected, &recovery, true).await;
    admitted(&fixture.state, original_revision).await;
    assert!(
        fixture
            .state
            .supervisor_sessions
            .is_current_session("sandbox", &accepted.session_id)
    );
}
