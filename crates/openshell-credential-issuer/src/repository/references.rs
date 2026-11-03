// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Scoped versioned metadata with transactional, value-free change publication.

use super::{Change, Mutation, Repository, ScopedRepository};
use crate::auth::GatewayScope;
use crate::{
    ReferenceRegistry, ReferenceState, ReferenceStateStore, ReferenceWrite, StoredReference,
};
use async_trait::async_trait;
use std::sync::Arc;
use tonic::Status;

const KIND: &str = "credential-reference-v1";
#[derive(Debug, Clone)]
pub struct ReferenceRepository {
    store: ScopedRepository,
    scope: GatewayScope,
}
impl Repository {
    pub fn references(self: &Arc<Self>, scope: &GatewayScope) -> ReferenceRepository {
        ReferenceRepository {
            store: self.for_gateway(scope),
            scope: scope.clone(),
        }
    }
}
impl ReferenceRepository {
    pub fn registry(&self) -> ReferenceRegistry {
        ReferenceRegistry::new(Arc::new(self.clone()))
    }
    pub fn storage(&self) -> &ScopedRepository {
        &self.store
    }
    /// Prepare fenced metadata and event writes, allowing the service to commit
    /// grant receipts and owner checks in the same native transaction. No value
    /// or driver side effects occur here. Cleanup acknowledgments remain the
    /// caller's responsibility and must follow confirmed backend deletion.
    pub async fn prepare(
        &self,
        reference: &str,
        expected: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(Mutation, Option<Change>), Status> {
        self.scope.authorize_owner(&state.owner)?;
        crate::authorize(state, &state.owner)?;
        let old = self.load(reference).await?;
        match (&old, expected) {
            (None, None) => {
                if state.version != 1 {
                    return Err(Status::invalid_argument(
                        "new credential reference must start at version one",
                    ));
                }
            }
            (Some(_), None) => {
                return Err(Status::already_exists(
                    "credential reference already exists",
                ));
            }
            (Some(old), Some(revision)) if old.revision == revision => {
                if old.state.owner != state.owner {
                    return Err(Status::permission_denied(
                        "credential reference owner is immutable",
                    ));
                }
                let same_value = old.state.backing == state.backing
                    && old.state.expiration_time_ms == state.expiration_time_ms
                    && old.state.revoked == state.revoked;
                let valid_transition = if state.version == old.state.version {
                    same_value
                } else {
                    !old.state.revoked && old.state.version.checked_add(1) == Some(state.version)
                };
                if !valid_transition {
                    return Err(Status::failed_precondition(
                        "invalid credential reference version transition",
                    ));
                }
                if (!same_value && (old.state.backing != state.backing || state.revoked))
                    && !state.pending_deletions.contains(&old.state.backing)
                {
                    return Err(Status::failed_precondition(
                        "retired credential backing must remain owned",
                    ));
                }
            }
            _ => return Err(Status::aborted("credential reference revision changed")),
        }
        let changed = old
            .as_ref()
            .is_none_or(|old| old.state.version != state.version);
        let payload = serde_json::to_vec(state)
            .map_err(|_| Status::internal("credential reference encoding failed"))?;
        Ok((
            Mutation::Put {
                kind: KIND.to_string(),
                key: reference.to_string(),
                expected,
                payload,
            },
            changed.then(|| Change {
                kind: "secret".to_string(),
                key: reference.to_string(),
                version: state.version,
                deleted: state.revoked,
            }),
        ))
    }
    pub async fn prepare_many(
        &self,
        writes: &[ReferenceWrite],
    ) -> Result<(Vec<Mutation>, Vec<Change>), Status> {
        let mut mutations = Vec::with_capacity(writes.len());
        let mut changes = Vec::new();
        for write in writes {
            let (mutation, change) = self
                .prepare(
                    &write.reference,
                    Some(write.expected_revision),
                    &write.state,
                )
                .await?;
            mutations.push(mutation);
            changes.extend(change);
        }
        Ok((mutations, changes))
    }
}
#[async_trait]
impl ReferenceStateStore for ReferenceRepository {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status> {
        let Some(record) = self.store.load(KIND, reference).await? else {
            return Ok(None);
        };
        let state: ReferenceState = serde_json::from_slice(&record.payload)
            .map_err(|_| Status::data_loss("invalid credential reference metadata"))?;
        self.scope.authorize_owner(&state.owner)?;
        crate::authorize(&state, &state.owner)?;
        Ok(Some(StoredReference {
            revision: record.revision,
            state,
        }))
    }
    async fn compare_and_swap(
        &self,
        reference: &str,
        expected_revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status> {
        let (mutation, change) = self.prepare(reference, expected_revision, state).await?;
        self.store
            .commit(&[mutation], &change.into_iter().collect::<Vec<_>>())
            .await?;
        Ok(())
    }
    async fn compare_and_swap_many(&self, writes: &[ReferenceWrite]) -> Result<(), Status> {
        let (mutations, changes) = self.prepare_many(writes).await?;
        self.store.commit(&mutations, &changes).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
