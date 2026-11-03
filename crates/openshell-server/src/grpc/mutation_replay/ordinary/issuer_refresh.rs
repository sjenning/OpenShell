// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Explicit scalar allowlist: never serialize a public response, issuer request,
//! credentials, backend handles, or upstream error text into the gateway ledger.
use super::{Store, replay_unavailable, uncertain};
use crate::credential_source::handoff::PublishedGrant;
use openshell_core::{
    ObjectName as _,
    proto::{ProviderCredentialRefreshRecoveryAction, ProviderCredentialRefreshStatus},
};
use serde::{Deserialize, Serialize};
use tonic::Status;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::grpc) struct IssuerRefresh {
    binding: PublishedGrant,
    state: String,
    expiration_ms: Option<i64>,
    next_refresh_ms: Option<i64>,
    recovery_action: i32,
    failure_code: String,
}
impl IssuerRefresh {
    pub(super) fn capture(
        binding: PublishedGrant,
        status: &ProviderCredentialRefreshStatus,
    ) -> Result<Self, Status> {
        if status.provider_id != binding.provider_id
            || status.credential_key != binding.credential_key
            || status.strategy_name != binding.strategy_name
        {
            return Err(uncertain());
        }
        let value = Self {
            binding,
            state: status.status.clone(),
            expiration_ms: status
                .expiration_time
                .as_ref()
                .map(openshell_core::time::timestamp_to_millis)
                .transpose()
                .map_err(|_| uncertain())?,
            next_refresh_ms: status
                .next_refresh_time
                .as_ref()
                .map(openshell_core::time::timestamp_to_millis)
                .transpose()
                .map_err(|_| uncertain())?,
            recovery_action: status.recovery_action,
            failure_code: status.failure_code.clone(),
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Status> {
        if !matches!(
            self.state.as_str(),
            "configured"
                | "refreshing"
                | "publishing"
                | "refreshed"
                | "failed"
                | "parked"
                | "deleting"
                | "deleted"
        ) || self.failure_code.len() > 128
            || !self
                .failure_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || ProviderCredentialRefreshRecoveryAction::try_from(self.recovery_action).is_err()
        {
            return Err(replay_unavailable());
        }
        Ok(())
    }
    pub(super) async fn restore(
        self,
        store: &Store,
    ) -> Result<ProviderCredentialRefreshStatus, Status> {
        self.validate()?;
        let provider = self
            .binding
            .restore(store)
            .await
            .map_err(|_| replay_unavailable())?;
        // Reuse canonical strategy/recovery projection, then restore only the
        // explicitly allowlisted result metadata captured by the admitted call.
        let strategy = if self.binding.strategy_name.starts_with("custom:") {
            0
        } else {
            openshell_providers::resolve_refresh_strategy(0, &self.binding.strategy_name)
                .map_err(|_| replay_unavailable())? as i32
        };
        Ok(ProviderCredentialRefreshStatus {
            provider: provider.object_name().into(),
            provider_id: self.binding.provider_id,
            credential_key: self.binding.credential_key,
            strategy,
            strategy_name: self.binding.strategy_name,
            status: self.state,
            expiration_time: self
                .expiration_ms
                .map(openshell_core::time::timestamp_from_millis)
                .transpose()
                .map_err(|_| replay_unavailable())?,
            next_refresh_time: self
                .next_refresh_ms
                .map(openshell_core::time::timestamp_from_millis)
                .transpose()
                .map_err(|_| replay_unavailable())?,
            recovery_action: self.recovery_action,
            failure_code: self.failure_code,
            ..Default::default()
        })
    }
}
