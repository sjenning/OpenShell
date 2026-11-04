// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Remote provider mutations never enter local credential storage.
mod configuration;
mod custom;
mod refresh;
use crate::{
    credential_source::{
        RemoteProviderSource,
        handoff::{ExpirationIntent, StaticHandoff},
    },
    persistence::{AtomicWrite, Store},
};
pub(super) use configuration::{Configuration, configure};
pub(super) use custom::configure_custom;
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _, proto::Provider};
use prost::Message as _;
pub(super) use refresh::delete_refresh;
pub(super) use refresh::rotate;
use std::collections::HashMap;
use tonic::Status;

pub(super) async fn stage(
    store: &Store,
    source: &RemoteProviderSource,
    candidate: &mut Provider,
    values: &HashMap<String, String>,
    expected: Option<u64>,
) -> Result<Option<StaticHandoff>, Status> {
    if values.is_empty() {
        return Ok(None);
    }
    let keys = values.keys().cloned().collect::<Vec<_>>();
    let mut handoff = StaticHandoff::begin(store, source, candidate, &keys, expected).await?;
    let result = async {
        handoff.reserve(store, source).await?;
        let expirations = candidate
            .credential_expiration_times
            .iter()
            .filter(|(key, _)| values.contains_key(*key))
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        handoff.fill(store, source, values, &expirations).await?;
        handoff.handles(source)
    }
    .await;
    match result {
        Ok(handles) => {
            candidate.credential_handles.extend(handles);
            candidate.credentials.clear();
            Ok(Some(handoff))
        }
        Err(error) => {
            let _ = handoff.abort(store, source).await;
            Err(error)
        }
    }
}
pub(super) async fn publish(
    store: &Store,
    source: &RemoteProviderSource,
    candidate: &Provider,
    existing: Option<&Provider>,
    expected: Option<u64>,
    handoff: Option<&mut StaticHandoff>,
) -> Result<u64, Status> {
    // Keep the optional intent path out of every configure/rotate caller's
    // stack-resident future, including mutation replay's dispatch enum.
    Box::pin(publish_with_expiration_intent(
        store, source, candidate, existing, expected, handoff, None,
    ))
    .await
}
pub(super) async fn publish_with_expiration_intent(
    store: &Store,
    source: &RemoteProviderSource,
    candidate: &Provider,
    existing: Option<&Provider>,
    expected: Option<u64>,
    handoff: Option<&mut StaticHandoff>,
    expiration_intent: Option<&ExpirationIntent>,
) -> Result<u64, Status> {
    let owned = if let Some(existing) = existing {
        StaticHandoff::published_for_provider(store, source, existing).await?
    } else {
        Vec::new()
    };
    let version = expected
        .map_or(Some(1), |value| value.checked_add(1))
        .ok_or_else(|| Status::resource_exhausted("provider resource version exhausted"))?;
    if let Some(handoff) = handoff {
        let write = expected.map_or_else(
            || AtomicWrite::Create {
                object_type: "provider".into(),
                id: candidate.object_id().into(),
                name: candidate.object_name().into(),
                workspace: candidate.object_workspace().into(),
                payload: candidate.encode_to_vec(),
            },
            |expected_version| AtomicWrite::Update {
                object_type: "provider".into(),
                id: candidate.object_id().into(),
                payload: candidate.encode_to_vec(),
                expected_version,
            },
        );
        handoff
            .publish_replacing_with_expiration_intent(
                store,
                source,
                write,
                &owned,
                expiration_intent,
            )
            .await?;
    } else if let Some(expected) = expected {
        StaticHandoff::update_preserving_with_expiration_intent(
            store,
            source,
            candidate,
            expected,
            &owned,
            expiration_intent,
        )
        .await?;
    } else {
        store
            .write_atomically(&[AtomicWrite::CreateLabeled {
                object_type: "provider".into(),
                id: candidate.object_id().into(),
                name: candidate.object_name().into(),
                workspace: candidate.object_workspace().into(),
                payload: candidate.encode_to_vec(),
                labels: candidate
                    .metadata
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("provider metadata missing"))?
                    .labels
                    .clone(),
            }])
            .await
            .map_err(super::provider_update_persistence_error_to_status)?;
    }
    Ok(version)
}
