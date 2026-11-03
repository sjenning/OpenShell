// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Pre-effect admission, and best-effort local bookkeeping after remote commit.
use super::{Inner, cache, refresh, store, tracking};
use std::collections::HashMap;
use tonic::Status;

pub(super) fn output_owners(
    owner: Option<store::SecretOwner>,
    outputs: &HashMap<String, String>,
) -> Result<HashMap<String, store::SecretOwner>, Status> {
    let owner = tracking::owner(
        owner.ok_or_else(|| Status::invalid_argument("issuer owner is required"))?,
    )?;
    if outputs.is_empty() || outputs.len() > 64 {
        return Err(Status::invalid_argument("invalid issuer grant outputs"));
    }
    outputs
        .iter()
        .map(|(id, key)| {
            Ok((
                id.clone(),
                tracking::owner(store::SecretOwner {
                    credential_key: key.clone(),
                    ..owner.clone()
                })?,
            ))
        })
        .collect()
}
pub(super) fn bindings(
    owners: &HashMap<String, store::SecretOwner>,
    references: &HashMap<String, String>,
) -> Vec<(String, store::SecretOwner)> {
    // RemoteIssuer validates the complete output ID set before returning success.
    references
        .iter()
        .map(|(id, reference)| (reference.clone(), owners[id].clone()))
        .collect()
}
impl Inner {
    pub fn mutation_status(
        &self,
        mut before: tracking::Observation,
        status: Option<&refresh::GrantStatus>,
        invalidate: bool,
    ) -> Result<(), Status> {
        {
            // Preserve fences for concurrent grant observations, but let this
            // mutation publish its own validated status. Secret and grant
            // checkpoints must not invalidate each other's metadata reads.
            let mut state = self.lock()?;
            let unchanged = state.grant_generation == before.metadata_generation;
            state.grant_generation = state.grant_generation.wrapping_add(1);
            if unchanged {
                before.metadata_generation = state.grant_generation;
            }
            if invalidate {
                state.clear_values();
                state.secret_generation = state.secret_generation.wrapping_add(1);
                state.secrets_reconciled = false;
                for entry in state.secrets.values_mut() {
                    entry.metadata = None;
                }
            }
        }
        if invalidate {
            self.send(super::IssuerChange::Unknown(super::ChangeKind::Secrets));
        }
        if let Some(status) = status {
            cache::grant(self, status, &before)?;
        }
        Ok(())
    }
}
