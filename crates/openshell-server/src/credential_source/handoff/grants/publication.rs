// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free publication proof for gateway mutation replay. Grant IDs identify
//! immutable issuer authorization epochs, not permission to mint again.
use super::{Phase, Provider, StaticHandoff, Store, invalid};
use crate::credential_source::{DRIVER, IssuerReferenceBinding};
use openshell_core::{ObjectId as _, ObjectWorkspace as _};
use serde::{Deserialize, Serialize};
use tonic::Status;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedGrant {
    pub journal: String,
    pub source: String,
    pub workspace: String,
    pub provider_id: String,
    pub credential_key: String,
    pub credential_keys: Vec<String>,
    pub strategy_name: String,
    pub grant: String,
}
impl StaticHandoff {
    /// Capture only a complete published bundle still bound to this provider.
    /// Neither display names nor provider resource versions establish ownership.
    pub(crate) fn published_grant(&self, provider: &Provider) -> Result<PublishedGrant, Status> {
        let grant = self.state.grant.as_ref().ok_or_else(invalid)?;
        let id = grant.id.as_deref().ok_or_else(invalid)?;
        if self.state.phase != Phase::Published
            || self.state.provider_id != provider.object_id()
            || self.state.workspace != provider.object_workspace()
            || !provider.credentials.is_empty()
            || provider
                .metadata
                .as_ref()
                .is_none_or(|metadata| metadata.deletion_time.is_some())
        {
            return Err(invalid());
        }
        for (key, slot) in &self.state.slots {
            let handle = provider.credential_handles.get(key).ok_or_else(invalid)?;
            if slot.retiring || handle.driver != DRIVER || handle.handle.len() > 1024 {
                return Err(invalid());
            }
            let binding: IssuerReferenceBinding =
                serde_json::from_str(&handle.handle).map_err(|_| invalid())?;
            if binding.version != 1
                || binding.source != self.state.source
                || binding.grant.as_deref() != Some(id)
                || Some(&binding.reference) != slot.reference.as_ref()
            {
                return Err(invalid());
            }
        }
        Ok(PublishedGrant {
            journal: self.state.id.clone(),
            source: self.state.source.clone(),
            workspace: self.state.workspace.clone(),
            provider_id: self.state.provider_id.clone(),
            credential_key: grant.plan.credential_key.clone(),
            credential_keys: self.state.slots.keys().cloned().collect(),
            strategy_name: grant.plan.strategy.clone(),
            grant: id.into(),
        })
    }
}
impl PublishedGrant {
    /// Metadata-only replay fence. Retirement, rebinding, epoch changes, missing
    /// siblings, and missing journals cannot authorize replay or a new mint.
    pub(crate) async fn restore(&self, store: &Store) -> Result<Provider, Status> {
        let handoff = StaticHandoff::load(store, &self.journal)
            .await?
            .ok_or_else(invalid)?;
        let provider = store
            .get_message::<Provider>(&self.provider_id)
            .await
            .map_err(|_| invalid())?
            .ok_or_else(invalid)?;
        if handoff.published_grant(&provider)? != *self {
            return Err(invalid());
        }
        Ok(provider)
    }
}
