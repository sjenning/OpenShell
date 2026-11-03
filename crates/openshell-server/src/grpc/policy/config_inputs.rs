// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Store state shared by the sandbox configuration and provider environment
//! builders.
//!
//! Both builders read the provider catalog, provider records, global settings,
//! and the latest sandbox policy. Loading them once per build attempt lets one
//! attempt hand both components the same view of those sources. The reads are
//! independent, not one database transaction, and credential values are
//! resolved later by the provider builder alone.

use openshell_core::proto::Sandbox;
use tonic::Status;

use super::super::StoredSettings;
use super::super::provider::{
    ProviderEnvironmentRecord, load_provider_environment_records_with_source,
};
use super::load_global_settings;
use crate::ServerState;
use crate::persistence::{ObjectId, ObjectWorkspace, PolicyRecord};
use crate::policy_store::PolicyStoreExt as _;
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;

/// Inputs captured for one sandbox and one build attempt.
///
/// Callers must authorize access to `sandbox` before loading. Load again for
/// every later build or retry so a newer source is never hidden.
pub struct SandboxConfigInputs {
    pub(super) sandbox: Sandbox,
    pub(super) catalog: EffectiveProviderProfileCatalog,
    /// Records in `spec.providers` order, which the provider revision hashes.
    pub(super) provider_records: Vec<ProviderEnvironmentRecord>,
    pub(super) global_settings: StoredSettings,
    /// Observed for its version metadata even under a global policy, whose
    /// dormant sandbox payload is never decoded.
    pub(super) latest_policy: Option<PolicyRecord>,
    /// Only an explicitly selected external metadata source may defer an
    /// availability error. Policy/settings remain deliverable, but these
    /// inputs must never resolve or cache a provider environment.
    pub(super) credential_metadata_error: Option<Box<Status>>,
}

impl SandboxConfigInputs {
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    pub(super) fn delivery_provider_revision(&self, revision: u64) -> Result<u64, Status> {
        if self.credential_metadata_error.is_none() {
            return Ok(revision);
        }
        let mut bytes = b"openshell-unavailable-provider-metadata-v1".to_vec();
        bytes.extend_from_slice(&revision.to_le_bytes());
        let digest = openshell_crypto::sha256(&bytes)
            .map_err(|_| Status::internal("provider metadata failure fingerprint failed"))?;
        Ok(u64::from_le_bytes(
            digest[..8].try_into().expect("hash prefix"),
        ))
    }
}

/// Load the inputs both configuration builders share. Independent reads run
/// concurrently; a failure here fails every component built from them.
pub async fn load_sandbox_config_inputs(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    // Keep the shared concurrent read tree off every enclosing RPC/mutation
    // future's stack, including callers that also capture readiness snapshots.
    Box::pin(load_inputs(state, sandbox, false)).await
}

/// Capture a configuration for a poll or a new push session. Defer only
/// external metadata availability failures until environment construction,
/// allowing delivery of an explicit static-credential invalidation without a
/// previous session's cached configuration. Store and validation errors still
/// fail the read normally.
pub async fn load_sandbox_config_inputs_for_delivery(
    state: &ServerState,
    sandbox: Sandbox,
) -> Result<SandboxConfigInputs, Status> {
    Box::pin(load_inputs(state, sandbox, true)).await
}

async fn load_inputs(
    state: &ServerState,
    sandbox: Sandbox,
    for_delivery: bool,
) -> Result<SandboxConfigInputs, Status> {
    let store = state.store.as_ref();
    let workspace = sandbox.object_workspace();
    let provider_names = sandbox
        .spec
        .as_ref()
        .map(|spec| spec.providers.as_slice())
        .unwrap_or_default();
    let selected_source = if for_delivery {
        crate::config_delivery::credential_metadata::Source::for_delivery(state)
    } else {
        crate::config_delivery::credential_metadata::Source::selected(state)
    };
    let credential_source: &dyn crate::credential_source::ProviderCredentialSource =
        match selected_source.as_ref() {
            Some(source) => source,
            None => state.provider_credential_source(),
        };
    let (catalog, provider_records, global_settings, latest_policy) = tokio::try_join!(
        state
            .provider_profile_sources
            .snapshot_catalog(store, workspace),
        load_provider_environment_records_with_source(
            store,
            workspace,
            provider_names,
            Some(credential_source)
        ),
        load_global_settings(store),
        async {
            store
                .get_latest_policy(sandbox.object_id())
                .await
                .map_err(|e| Status::internal(format!("fetch policy history failed: {e}")))
        },
    )?;
    Ok(SandboxConfigInputs {
        sandbox,
        catalog,
        provider_records,
        global_settings,
        latest_policy,
        credential_metadata_error: selected_source.and_then(|source| source.take_unavailable()),
    })
}
