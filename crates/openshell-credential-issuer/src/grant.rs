// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Grant admission policy over non-secret durable checkpoints.
//!
//! Adapters reload under the distributed lease and retain revision-fenced persistence; a worker's
//! scheduling snapshot is never sufficient authority to mint.

use crate::{
    SecretOwner, engine::RefreshTrigger, minter::RecoveryAction, scheduler::GrantSchedule,
};
use tonic::Status;

/// Immutable grant identity.
///
/// Reauthorization changes the epoch even when the storage object ID is retained. Display names and storage revisions are not
/// identity: ordinary cleanup can advance the latter without replacing a grant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrantIdentity {
    pub id: String,
    pub authorization_epoch: String,
    pub owner: SecretOwner,
}

/// Non-secret projection, not an independent durable format.
///
/// Legacy adapters retain their serialization and supply an effective epoch for old records.
/// Identity equality is a mutation fence, not authentication of the caller.
#[derive(Debug, Clone)]
pub struct GrantCheckpoint {
    pub identity: GrantIdentity,
    pub status: String,
    pub failure_code: String,
    pub completed_attempt: Option<String>,
    pub schedule: GrantSchedule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAdmission {
    /// A new completed mint satisfies this caller's observed generation.
    Current,
    Prepare,
}

impl GrantCheckpoint {
    /// Call on freshly reloaded state under the lease, before resolving values
    /// or making maintenance writes. Coalescing must not cross an owner, grant,
    /// authorization epoch, or deletion boundary.
    pub fn admit(&self, observed: &Self) -> Result<GrantAdmission, Status> {
        if [&self.identity, &observed.identity]
            .iter()
            .any(|identity| identity.id.is_empty() || identity.authorization_epoch.is_empty())
        {
            return Err(Status::failed_precondition(
                "credential refresh grant identity is missing",
            ));
        }
        if self.identity != observed.identity {
            return Err(Status::aborted("provider refresh was reconfigured"));
        }
        self.ensure_not_deleting()?;
        if self.status == "refreshed"
            && self.receipt().is_some()
            && self.receipt() != observed.receipt()
        {
            return Ok(GrantAdmission::Current);
        }
        Ok(GrantAdmission::Prepare)
    }

    /// After admission and adapter-specific owner liveness checks, reject any
    /// unresolved exchange even for explicit rotations. Manual rotation skips
    /// retry backoff, never an uncertain upstream side effect.
    pub fn ensure_mintable(&self, trigger: RefreshTrigger, now_ms: i64) -> Result<(), Status> {
        self.ensure_not_deleting()?;
        if matches!(
            self.status.as_str(),
            "refresh_in_progress" | "refresh_committing"
        ) || self.failure_code == "oauth_refresh_exchange_uncertain"
            || (self.schedule.recovery_action == Some(RecoveryAction::Investigate)
                && self.schedule.next_refresh_at_ms == i64::MAX)
        {
            return Err(Status::failed_precondition(
                "previous credential mint has an uncertain outcome; reconfigure the refresh grant",
            ));
        }
        if trigger == RefreshTrigger::Automatic {
            self.schedule.ensure_automatic_ready(now_ms)?;
        }
        Ok(())
    }

    fn ensure_not_deleting(&self) -> Result<(), Status> {
        if self.schedule.deleting {
            return Err(Status::failed_precondition(
                "provider refresh is being deleted",
            ));
        }
        Ok(())
    }

    fn receipt(&self) -> Option<&str> {
        self.completed_attempt
            .as_deref()
            .filter(|id| !id.is_empty())
    }
}

#[cfg(test)]
mod tests;
