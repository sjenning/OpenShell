// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Claim old ownership in the same transaction that removes its live bindings.
use super::{
    AtomicWrite, Phase, Provider, RemoteProviderSource, StaticHandoff, Store, encode, invalid,
    storage,
};
use openshell_core::{ObjectId as _, ObjectWorkspace as _};
use prost::Message as _;
use std::collections::HashSet;
use tonic::Status;
pub(super) fn claims(
    source: &RemoteProviderSource,
    provider: &Provider,
    replacement: Option<&Provider>,
    owned: &[StaticHandoff],
) -> Result<Vec<AtomicWrite>, Status> {
    if !provider.credentials.is_empty() {
        return Err(invalid());
    }
    let mut ids = HashSet::new();
    for old in owned {
        old.source(source)?;
        if old.state.phase != Phase::Published
            || old.state.provider_id != provider.object_id()
            || old.state.workspace != provider.object_workspace()
            || !ids.insert(old.id())
        {
            return Err(invalid());
        }
    }
    // Never infer ownership merely from a missing parent or from a display name.
    // Every current binding must have a durable, immutable-owner journal.
    for (key, handle) in &provider.credential_handles {
        let binding = source.decode(handle)?;
        if !owned.iter().any(|old| {
            old.grant_id() == binding.grant.as_deref()
                && old
                    .state
                    .slots
                    .get(key)
                    .filter(|slot| !slot.retiring)
                    .and_then(|slot| slot.reference.as_ref())
                    == Some(&binding.reference)
        }) {
            return Err(Status::failed_precondition(
                "issuer binding retirement ownership is missing",
            ));
        }
    }
    let remaining = replacement
        .map(|provider| {
            provider
                .credential_handles
                .iter()
                .map(|(key, handle)| {
                    let binding = source.decode(handle)?;
                    Ok((key.clone(), (binding.reference, binding.grant)))
                })
                .collect::<Result<std::collections::HashMap<_, _>, Status>>()
        })
        .transpose()?
        .unwrap_or_default();
    owned
        .iter()
        .map(|old| {
            let mut state = old.state.clone();
            for (key, slot) in &mut state.slots {
                let preserved = remaining.get(key).is_some_and(|(reference, grant)| {
                    slot.reference.as_ref() == Some(reference) && grant.as_deref() == old.grant_id()
                });
                if !preserved {
                    slot.retiring = true;
                }
            }
            if state.grant.is_some()
                && state.slots.values().any(|slot| slot.retiring)
                && state.slots.values().any(|slot| !slot.retiring)
            {
                return Err(Status::failed_precondition(
                    "issuer grant outputs must be retired together",
                ));
            }
            if state.slots.values().all(|slot| slot.retiring) {
                state.phase = Phase::Aborting;
            }
            Ok(AtomicWrite::Update {
                object_type: super::KIND.into(),
                id: old.id().into(),
                expected_version: old.revision,
                payload: encode(&state)?,
            })
        })
        .collect()
}
impl StaticHandoff {
    /// Remove a provider and claim all supplied published ownership journals in
    /// one gateway transaction. No issuer deletion starts before this commits.
    /// Current bindings must be completely covered by those journals.
    pub async fn delete_provider(
        store: &Store,
        source: &RemoteProviderSource,
        provider_id: &str,
        expected_version: u64,
        owned: &[Self],
    ) -> Result<(), Status> {
        let row = store
            .get("provider", provider_id)
            .await
            .map_err(storage)?
            .ok_or_else(|| Status::not_found("handoff provider not found"))?;
        if row.resource_version != expected_version {
            return Err(Status::aborted("handoff provider changed"));
        }
        let provider = Provider::decode(row.payload.as_slice()).map_err(|_| invalid())?;
        if provider.object_id() != provider_id || provider.object_workspace() != row.workspace {
            return Err(invalid());
        }
        let mut writes = claims(source, &provider, None, owned)?;
        writes.push(AtomicWrite::Delete {
            object_type: "provider".into(),
            id: provider_id.into(),
            expected_version,
        });
        store.write_atomically(&writes).await.map_err(storage)?;
        Ok(())
    }
    /// A known committed publication can be distinguished after losing its DB
    /// response without repeating any value-bearing operation.
    pub fn is_published(&self) -> bool {
        self.state.phase == Phase::Published
    }
    pub fn provider_id(&self) -> &str {
        &self.state.provider_id
    }
}
