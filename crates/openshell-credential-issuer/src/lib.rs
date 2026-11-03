// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Embedded issuer reference state. Values remain in credential drivers; this
//! crate owns stable identities, versions, revocation, cleanup ownership, local
//! refresh coordination, and the stateless minter contract.

pub mod auth;
pub mod backend;
pub mod builtins;
pub mod engine;
pub mod grant;
pub mod minter;
pub mod refresh;
pub mod remote_minter;
pub mod repository;
pub mod scheduler;

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tonic::{Code, Status};

const RETRIES: usize = 16;

/// Immutable authorization scope. Display names are deliberately excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretOwner {
    pub workspace: String,
    pub provider_id: String,
    pub credential_key: String,
}

/// Durable, non-secret reference metadata. `backing` is an encoded opaque
/// driver handle, never a credential value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceState {
    pub owner: SecretOwner,
    pub version: u64,
    pub backing: Vec<u8>,
    pub expiration_time_ms: Option<i64>,
    pub revoked: bool,
    /// Retired handles remain owned until their backend deletion succeeds.
    pub pending_deletions: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct StoredReference {
    pub state: ReferenceState,
    /// Storage revision, independent of credential version. Cleanup changes
    /// this revision without changing the observable credential version.
    pub revision: u64,
}

/// One staged value replacement. Secret values have already been stored under
/// fresh immutable backing handles; this request contains no credential values.
#[derive(Debug, Clone)]
pub struct ReferenceReplacement {
    pub reference: String,
    pub owner: SecretOwner,
    pub expected_version: u64,
    pub backing: Vec<u8>,
    pub expiration_time_ms: Option<i64>,
}

/// A prepared, revision-fenced reference update. Durable adapters can combine
/// these writes with grant receipts and owner fences in one native transaction.
#[derive(Debug, Clone)]
pub struct ReferenceWrite {
    pub reference: String,
    pub expected_revision: u64,
    pub state: ReferenceState,
}

/// Implementations must make the entire state replacement atomic. `None`
/// means create-only; stale writes return `ABORTED` or `ALREADY_EXISTS`.
#[async_trait]
pub trait ReferenceStateStore: std::fmt::Debug + Send + Sync {
    async fn load(&self, reference: &str) -> Result<Option<StoredReference>, Status>;
    async fn compare_and_swap(
        &self,
        reference: &str,
        expected_revision: Option<u64>,
        state: &ReferenceState,
    ) -> Result<(), Status>;

    /// All writes commit together or none do. Never implement this by looping
    /// over individual CAS calls. The default supports only a single write.
    async fn compare_and_swap_many(&self, writes: &[ReferenceWrite]) -> Result<(), Status> {
        match writes {
            [write] => {
                self.compare_and_swap(
                    &write.reference,
                    Some(write.expected_revision),
                    &write.state,
                )
                .await
            }
            [] => Err(Status::invalid_argument(
                "credential replacement batch is empty",
            )),
            _ => Err(Status::failed_precondition(
                "reference store does not support atomic batches",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReferenceRegistry {
    store: Arc<dyn ReferenceStateStore>,
}

impl ReferenceRegistry {
    #[must_use]
    pub fn new(store: Arc<dyn ReferenceStateStore>) -> Self {
        Self { store }
    }

    /// Observe without adopting an unregistered legacy handle.
    pub async fn observe(
        &self,
        reference: &str,
        owner: &SecretOwner,
    ) -> Result<Option<ReferenceState>, Status> {
        self.inspect(reference, owner)
            .await?
            .map(|state| {
                ensure_live(&state)?;
                Ok(state)
            })
            .transpose()
    }

    /// Authorized metadata observation, including tombstones. A revoked
    /// version must still invalidate snapshots before value resolution fails.
    pub async fn inspect(
        &self,
        reference: &str,
        owner: &SecretOwner,
    ) -> Result<Option<ReferenceState>, Status> {
        self.store
            .load(reference)
            .await?
            .map(|record| {
                authorize(&record.state, owner)?;
                Ok(record.state)
            })
            .transpose()
    }

    /// Idempotently adopt an existing handle as version one. An existing
    /// tombstone is authoritative and must never be recreated as a live epoch.
    pub async fn adopt(
        &self,
        reference: &str,
        owner: &SecretOwner,
        backing: Vec<u8>,
    ) -> Result<ReferenceState, Status> {
        if owner.workspace.is_empty()
            || owner.provider_id.is_empty()
            || owner.credential_key.is_empty()
        {
            return Err(Status::invalid_argument(
                "credential ownership scope must be complete",
            ));
        }
        if reference.is_empty() || backing.is_empty() {
            return Err(Status::invalid_argument(
                "credential reference and backing must be nonempty",
            ));
        }
        for _ in 0..RETRIES {
            if let Some(state) = self.observe(reference, owner).await? {
                return Ok(state);
            }
            let state = ReferenceState {
                owner: owner.clone(),
                version: 1,
                backing: backing.clone(),
                expiration_time_ms: None,
                revoked: false,
                pending_deletions: Vec::new(),
            };
            match self.store.compare_and_swap(reference, None, &state).await {
                Ok(()) => return Ok(state),
                Err(error) if is_conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("credential reference adoption conflicted"))
    }

    /// Commit an already-staged immutable backing handle.
    ///
    /// The caller retains candidate ownership on failure and must establish that
    /// it was not published before cleanup. Replacements never change reference
    /// identity or authorization scope.
    pub async fn replace(
        &self,
        reference: &str,
        owner: &SecretOwner,
        expected_version: u64,
        backing: Vec<u8>,
        expiration_time_ms: Option<i64>,
    ) -> Result<ReferenceState, Status> {
        self.replace_many(&[ReferenceReplacement {
            reference: reference.to_string(),
            owner: owner.clone(),
            expected_version,
            backing,
            expiration_time_ms,
        }])
        .await?
        .pop()
        .ok_or_else(|| Status::internal("credential replacement returned no state"))
    }

    /// Validate and fence every output before publication. This has no side
    /// effects; a caller must commit ALL returned writes atomically, optionally
    /// with its durable grant receipt and owner-version checks. CAS conflicts
    /// require rebuilding the entire group, never retrying a subset.
    pub async fn prepare_replacements(
        &self,
        replacements: &[ReferenceReplacement],
    ) -> Result<Vec<ReferenceWrite>, Status> {
        use std::collections::HashSet;
        if replacements.is_empty() {
            return Err(Status::invalid_argument(
                "credential replacement batch is empty",
            ));
        }
        let mut references = HashSet::new();
        let mut candidates = HashSet::new();
        for replacement in replacements {
            if replacement.reference.is_empty()
                || replacement.backing.is_empty()
                || !references.insert(&replacement.reference)
                || !candidates.insert(&replacement.backing)
            {
                return Err(Status::invalid_argument(
                    "credential replacements require distinct references and fresh backing handles",
                ));
            }
        }
        let mut writes = Vec::with_capacity(replacements.len());
        for replacement in replacements {
            let record = self
                .store
                .load(&replacement.reference)
                .await?
                .ok_or_else(|| Status::not_found("credential reference not found"))?;
            let mut state = record.state;
            authorize(&state, &replacement.owner)?;
            ensure_live(&state)?;
            if state.version != replacement.expected_version {
                return Err(Status::aborted("credential reference version changed"));
            }
            if candidates.contains(&state.backing)
                || state
                    .pending_deletions
                    .iter()
                    .any(|backing| candidates.contains(backing))
            {
                return Err(Status::invalid_argument(
                    "replacement requires a fresh backing handle",
                ));
            }
            state.version = next_version(state.version)?;
            state.pending_deletions.push(std::mem::replace(
                &mut state.backing,
                replacement.backing.clone(),
            ));
            state.expiration_time_ms = replacement.expiration_time_ms;
            writes.push(ReferenceWrite {
                reference: replacement.reference.clone(),
                expected_revision: record.revision,
                state,
            });
        }
        Ok(writes)
    }

    /// Publish an entire output set atomically. On an ambiguous storage error,
    /// the caller retains candidate ownership until it can establish the result;
    /// an error is never permission to delete a possibly committed backing.
    pub async fn replace_many(
        &self,
        replacements: &[ReferenceReplacement],
    ) -> Result<Vec<ReferenceState>, Status> {
        for _ in 0..RETRIES {
            let writes = self.prepare_replacements(replacements).await?;
            match self.store.compare_and_swap_many(&writes).await {
                Ok(()) => return Ok(writes.into_iter().map(|write| write.state).collect()),
                Err(error) if is_conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("credential replacement conflicted"))
    }

    /// Persist revocation before deleting values. Idempotent retries retain
    /// both the tombstone and ownership of every not-yet-deleted handle.
    pub async fn revoke(
        &self,
        reference: &str,
        owner: &SecretOwner,
    ) -> Result<ReferenceState, Status> {
        for _ in 0..RETRIES {
            let record = self
                .store
                .load(reference)
                .await?
                .ok_or_else(|| Status::not_found("credential reference not found"))?;
            let mut state = record.state;
            authorize(&state, owner)?;
            if state.revoked {
                return Ok(state);
            }
            state.version = next_version(state.version)?;
            state.revoked = true;
            state.pending_deletions.push(state.backing.clone());
            match self
                .store
                .compare_and_swap(reference, Some(record.revision), &state)
                .await
            {
                Ok(()) => return Ok(state),
                Err(error) if is_conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("credential revocation conflicted"))
    }

    /// Retain ownership of a candidate whose replacement definitively failed.
    /// Never queue a live current value for cleanup, even if the caller's view
    /// of the preceding write outcome was stale.
    pub async fn abandon_candidate(
        &self,
        reference: &str,
        owner: &SecretOwner,
        backing: Vec<u8>,
    ) -> Result<ReferenceState, Status> {
        if backing.is_empty() {
            return Err(Status::invalid_argument(
                "credential backing must be nonempty",
            ));
        }
        for _ in 0..RETRIES {
            let record = self
                .store
                .load(reference)
                .await?
                .ok_or_else(|| Status::not_found("credential reference not found"))?;
            let mut state = record.state;
            authorize(&state, owner)?;
            if !state.revoked && state.backing == backing {
                return Err(Status::failed_precondition(
                    "cannot delete a live credential backing",
                ));
            }
            if state.pending_deletions.contains(&backing) {
                return Ok(state);
            }
            state.pending_deletions.push(backing.clone());
            match self
                .store
                .compare_and_swap(reference, Some(record.revision), &state)
                .await
            {
                Ok(()) => return Ok(state),
                Err(error) if is_conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("credential candidate cleanup conflicted"))
    }

    /// Acknowledge a successful backend deletion without advancing the value
    /// version. Concurrent rotations cannot lose newly queued cleanup work.
    pub async fn acknowledge_deletion(
        &self,
        reference: &str,
        owner: &SecretOwner,
        backing: &[u8],
    ) -> Result<(), Status> {
        for _ in 0..RETRIES {
            let record = self
                .store
                .load(reference)
                .await?
                .ok_or_else(|| Status::not_found("credential reference not found"))?;
            let mut state = record.state;
            authorize(&state, owner)?;
            if !state.pending_deletions.iter().any(|item| item == backing) {
                return Ok(());
            }
            state.pending_deletions.retain(|item| item != backing);
            match self
                .store
                .compare_and_swap(reference, Some(record.revision), &state)
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if is_conflict(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("credential cleanup conflicted"))
    }
}

fn authorize(state: &ReferenceState, owner: &SecretOwner) -> Result<(), Status> {
    if state.version == 0 || state.backing.is_empty() {
        return Err(Status::data_loss("invalid credential reference state"));
    }
    if &state.owner != owner {
        return Err(Status::permission_denied(
            "credential reference belongs to another owner",
        ));
    }
    Ok(())
}

fn ensure_live(state: &ReferenceState) -> Result<(), Status> {
    if state.revoked {
        return Err(Status::not_found("credential reference is revoked"));
    }
    Ok(())
}

fn next_version(version: u64) -> Result<u64, Status> {
    version
        .checked_add(1)
        .ok_or_else(|| Status::resource_exhausted("credential version exhausted"))
}

fn is_conflict(error: &Status) -> bool {
    matches!(error.code(), Code::AlreadyExists | Code::Aborted)
}

#[cfg(test)]
mod tests;
