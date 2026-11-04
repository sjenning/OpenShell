// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::{GetProviderRequest, ListProvidersRequest};

const KEY: &str = "OPENAI_API_KEY";

fn create() -> CreateProviderRequest {
    CreateProviderRequest {
        provider: Some(Provider {
            metadata: Some(meta("expiration-replay")),
            r#type: "openai".into(),
            credentials: HashMap::from([(KEY.into(), "private-initial-value".into())]),
            // Preserve sub-millisecond precision in the replay recipe too.
            credential_expiration_times: HashMap::from([(
                KEY.into(),
                prost_types::Timestamp {
                    seconds: 1,
                    nanos: 123_456_789,
                },
            )]),
            ..Default::default()
        }),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
    }
}

fn update(provider: &Provider, value: &str) -> UpdateProviderRequest {
    UpdateProviderRequest {
        provider: Some(Provider {
            metadata: provider.metadata.clone(),
            config: HashMap::from([("SETTING".into(), value.into())]),
            ..Default::default()
        }),
        workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        request_id: id(),
        ..Default::default()
    }
}

async fn stored(state: &ServerState, provider: &Provider) -> Provider {
    state
        .store
        .get_message(provider.object_id())
        .await
        .unwrap()
        .unwrap()
}

async fn assert_projection(
    state: &Arc<ServerState>,
    response: &ProviderResponse,
    before: &Provider,
    expiration: Option<i64>,
) -> Provider {
    let projected = response.provider.as_ref().unwrap();
    let current = stored(state, before).await;
    assert_eq!(current.credential_handles, before.credential_handles);
    assert_eq!(
        current.credential_expiration_times, before.credential_expiration_times,
        "response projection must not rewrite stored legacy expiration"
    );
    assert_eq!(
        projected.credential_expiration_times.get(KEY),
        expiration
            .map(|value| openshell_core::time::timestamp_from_millis(value).unwrap())
            .as_ref()
    );
    assert_eq!(projected.metadata, current.metadata);
    assert_eq!(projected.config, current.config);
    assert!(projected.credential_handles.is_empty());
    assert_eq!(projected.credentials[KEY], "REDACTED");
    let get = provider::handle_get_provider(
        state,
        authed_request(GetProviderRequest {
            name: "expiration-replay".into(),
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(get.provider.as_ref(), Some(projected));
    let list = provider::handle_list_providers(
        state,
        authed_request(ListProvidersRequest {
            workspace_scope: Some(openshell_core::proto::workspace_selector("default")),
            ..Default::default()
        }),
    )
    .await
    .unwrap()
    .into_inner();
    assert_eq!(list.providers, vec![projected.clone()]);
    current
}

async fn assert_receipts_are_value_free(state: &ServerState) {
    for row in state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap()
    {
        let receipt = String::from_utf8(row.payload).unwrap();
        assert!(!receipt.contains("private-initial-value"));
        assert!(!receipt.contains("private-rotated-value"));
        assert!(!receipt.contains("credential_handles"));
        assert!(receipt.len() < 64 * 1024);
    }
}

#[tokio::test]
async fn embedded_provider_replay_keeps_projected_expiration_and_explicit_absence() {
    let (_directory, state) = protected_state().await;
    let create = create();
    let created = run(&state, authed_request(create.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay(&state, create).await, created);
    let initial = stored(&state, created.provider.as_ref().unwrap()).await;
    let expires = crate::persistence::current_time_ms() + 60_000;
    let mut current = initial.clone();
    let mut previous = None;
    let mut obsolete = None;
    for (index, expiration) in [Some(expires), None, Some(expires + 60_000)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            state
                .credentials
                .rotate_provider_reference(
                    crate::credentials::references::provider_scope(&initial, KEY),
                    &initial.credential_handles[KEY],
                    index as u64 + 1,
                    "private-rotated-value",
                    expiration,
                )
                .await
                .unwrap(),
            index as u64 + 2
        );
        if let Some((request, response)) = previous.take() {
            // A later issuer version changes neither the provider revision nor
            // the already admitted response, including a captured empty map.
            assert_eq!(replay(&state, request).await, response);
        }
        if index == 2 {
            break;
        }
        let request = update(&current, &format!("value-{index}"));
        let response = run(&state, authed_request(request.clone()))
            .await
            .unwrap()
            .into_inner();
        current = assert_projection(&state, &response, &initial, expiration).await;
        assert_eq!(replay(&state, request.clone()).await, response);
        if let Some(obsolete) = obsolete.replace(request.clone()) {
            assert_eq!(
                reason(&run(&state, authed_request(obsolete)).await.unwrap_err()),
                "REQUEST_REPLAY_UNAVAILABLE",
                "captured expiration must not bypass the provider revision fence"
            );
            assert_eq!(stored(&state, &initial).await, current);
        }
        previous = Some((request, response));
    }
    assert_receipts_are_value_free(&state).await;
}

#[tokio::test]
async fn remote_provider_replay_keeps_expiration_snapshot_without_resolving_values() {
    use crate::credential_source::RemoteProviderSource;
    use openshell_core::proto::credentials::store::v1 as wire;
    use std::sync::atomic::Ordering;

    let (_directory, mut state) = protected_state().await;
    let issuer = crate::credential_source::tests::issuer::Issuer::start().await;
    Arc::get_mut(&mut state).unwrap().provider_source = Some(Arc::new(
        RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap(),
    ));
    let created = run(&state, authed_request(create()))
        .await
        .unwrap()
        .into_inner();
    let initial = stored(&state, created.provider.as_ref().unwrap()).await;
    let binding: serde_json::Value =
        serde_json::from_str(&initial.credential_handles[KEY].handle).unwrap();
    let expires = crate::persistence::current_time_ms() + 60_000;
    issuer.fail_resolves.store(true, Ordering::SeqCst);
    let before_reads = issuer.resolves.load(Ordering::SeqCst);
    let mut current = initial.clone();
    let mut previous = None;
    for (index, expiration) in [Some(expires), None, Some(expires + 60_000)]
        .into_iter()
        .enumerate()
    {
        issuer
            .watched
            .put_secret(wire::PutSecretRequest {
                owner: Some(wire::SecretOwner {
                    workspace: "default".into(),
                    provider_id: initial.object_id().into(),
                    credential_key: KEY.into(),
                    provider: "expiration-replay".into(),
                    ..Default::default()
                }),
                reference: binding["reference"].as_str().unwrap().into(),
                expected_version: Some(index as u64 + 2),
                value: "private-rotated-value".into(),
                expiration_time: expiration
                    .map(|value| openshell_core::time::timestamp_from_millis(value).unwrap()),
                idempotency_key: id(),
            })
            .await
            .unwrap();
        issuer
            .watched
            .wait_synchronized(std::time::Duration::from_secs(5))
            .await
            .unwrap();
        if let Some((request, response)) = previous.take() {
            assert_eq!(replay(&state, request).await, response);
        }
        if index == 2 {
            break;
        }
        let request = update(&current, &format!("remote-value-{index}"));
        let response = run(&state, authed_request(request.clone()))
            .await
            .unwrap()
            .into_inner();
        current = assert_projection(&state, &response, &initial, expiration).await;
        assert_eq!(replay(&state, request.clone()).await, response);
        previous = Some((request, response));
    }
    assert_eq!(issuer.resolves.load(Ordering::SeqCst), before_reads);
    assert_receipts_are_value_free(&state).await;
}

#[tokio::test]
async fn legacy_provider_receipt_without_expiration_snapshot_still_replays() {
    let (_directory, state) = protected_state().await;
    let request = create();
    let response = run(&state, authed_request(request.clone()))
        .await
        .unwrap()
        .into_inner();
    let rows = state
        .store
        .list_by_type_after(OBJECT_TYPE, None, 100)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    let mut admission: serde_json::Value = serde_json::from_slice(&row.payload).unwrap();
    admission["success"]["Ordinary"]["Provider"]
        .as_object_mut()
        .unwrap()
        .remove("expiration_times")
        .unwrap();
    state
        .store
        .put_if(
            OBJECT_TYPE,
            &row.id,
            &row.name,
            &row.workspace,
            &serde_json::to_vec(&admission).unwrap(),
            None,
            crate::persistence::WriteCondition::MatchResourceVersion(row.resource_version),
        )
        .await
        .unwrap();
    assert_eq!(replay(&state, request).await, response);
}
