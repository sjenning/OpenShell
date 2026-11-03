// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stateless minting contract. Minters receive values for one attempt, never
//! provider records, credential handles, storage drivers, or scheduling state.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tonic::Status;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MaterialDescriptor {
    pub name: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StrategyDescriptor {
    pub name: String,
    pub config: Vec<MaterialDescriptor>,
    pub secret_material: Vec<MaterialDescriptor>,
    /// Semantic output IDs, not environment variable names.
    pub outputs: Vec<String>,
    /// Allowed replacement material returned by the minter.
    pub rotated_secret_material: Vec<String>,
}

#[derive(Clone)]
pub struct MintRequest {
    pub strategy: String,
    pub config: HashMap<String, String>,
    pub secret_material: HashMap<String, String>,
    /// Allocated and durably recorded by the issuer before calling a minter.
    /// A minter can use it for upstream idempotency; it is not an auth token.
    pub attempt_id: String,
}

impl fmt::Debug for MintRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintRequest")
            .field("strategy", &self.strategy)
            .field("config", &"[REDACTED]")
            .field("secret_material", &"[REDACTED]")
            .field("attempt_id", &self.attempt_id)
            .finish()
    }
}

pub struct MintResponse {
    pub outputs: HashMap<String, String>,
    pub expiration_time_ms: i64,
    pub rotated_secret_material: HashMap<String, String>,
}

impl fmt::Debug for MintResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintResponse")
            .field("outputs", &"[REDACTED]")
            .field("expiration_time_ms", &self.expiration_time_ms)
            .field("rotated_secret_material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    Retry,
    Reauthorize,
    FixConfiguration,
    Investigate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrySchedule {
    Short,
    Configuration,
    Parked,
}

/// Classified mint failure, preserving ambiguous-exchange outcomes.
///
/// Implementations must not copy arbitrary upstream bodies into reasons or
/// subtypes, or flatten an uncertain exchange into a retryable transport error.
#[derive(Debug)]
pub struct MintFailure {
    pub status: Status,
    pub recovery_action: RecoveryAction,
    pub failure_code: &'static str,
    pub provider_error_subtype: Option<&'static str>,
    pub retry_schedule: RetrySchedule,
}

impl MintFailure {
    fn configuration(message: &'static str) -> Self {
        Self {
            status: Status::failed_precondition(message),
            recovery_action: RecoveryAction::FixConfiguration,
            failure_code: "minter_configuration_invalid",
            provider_error_subtype: None,
            retry_schedule: RetrySchedule::Configuration,
        }
    }

    fn invalid_response() -> Self {
        // An upstream side effect may already have happened. Do not silently
        // retry a malformed response or publish undeclared outputs/material.
        Self {
            status: Status::failed_precondition(
                "minter returned an invalid response; investigate the mint attempt",
            ),
            recovery_action: RecoveryAction::Investigate,
            failure_code: "minter_response_invalid",
            provider_error_subtype: None,
            retry_schedule: RetrySchedule::Parked,
        }
    }
}

#[async_trait]
pub trait TokenMinter: fmt::Debug + Send + Sync {
    /// Descriptions are pinned at registration, not changed during an attempt.
    fn describe(&self) -> StrategyDescriptor;
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure>;
}

#[derive(Debug)]
struct RegisteredMinter {
    descriptor: StrategyDescriptor,
    implementation: Arc<dyn TokenMinter>,
}

/// Build once at startup, then share immutably. Registration never replaces an
/// existing strategy, and operator extensions cannot claim built-in names.
#[derive(Debug, Default)]
pub struct MinterRegistry {
    entries: BTreeMap<String, RegisteredMinter>,
}

impl MinterRegistry {
    pub fn register_builtin(&mut self, minter: Arc<dyn TokenMinter>) -> Result<(), Status> {
        let descriptor = minter.describe();
        if !valid_id(&descriptor.name) {
            return Err(Status::invalid_argument("invalid built-in minter name"));
        }
        self.insert(descriptor, minter)
    }

    pub fn register_custom(&mut self, minter: Arc<dyn TokenMinter>) -> Result<(), Status> {
        let descriptor = minter.describe();
        if !descriptor
            .name
            .strip_prefix("custom:")
            .is_some_and(valid_id)
        {
            return Err(Status::invalid_argument(
                "custom minter names must use custom:<name>",
            ));
        }
        self.insert(descriptor, minter)
    }

    fn insert(
        &mut self,
        descriptor: StrategyDescriptor,
        implementation: Arc<dyn TokenMinter>,
    ) -> Result<(), Status> {
        let material_names: Vec<_> = descriptor
            .config
            .iter()
            .chain(&descriptor.secret_material)
            .map(|field| field.name.clone())
            .collect();
        if descriptor.outputs.is_empty()
            || !valid_ids(&descriptor.outputs)
            || !valid_ids(&material_names)
            || !valid_ids(&descriptor.rotated_secret_material)
            || descriptor.rotated_secret_material.iter().any(|name| {
                !descriptor
                    .secret_material
                    .iter()
                    .any(|field| field.name == *name)
            })
        {
            return Err(Status::invalid_argument("invalid minter descriptor"));
        }
        if self.entries.contains_key(&descriptor.name) {
            return Err(Status::already_exists("minter strategy already registered"));
        }
        self.entries.insert(
            descriptor.name.clone(),
            RegisteredMinter {
                descriptor,
                implementation,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn supports(&self, strategy: &str) -> bool {
        self.entries.contains_key(strategy)
    }

    pub fn describe(&self) -> impl Iterator<Item = &StrategyDescriptor> {
        self.entries.values().map(|entry| &entry.descriptor)
    }

    pub async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        let entry = self.entries.get(&request.strategy).ok_or_else(|| {
            MintFailure::configuration("refresh strategy has no registered minter")
        })?;
        if request.attempt_id.trim().is_empty()
            || request
                .config
                .keys()
                .any(|key| request.secret_material.contains_key(key))
            || entry
                .descriptor
                .secret_material
                .iter()
                .any(|field| request.config.contains_key(&field.name))
            || missing_required(&entry.descriptor.config, &request.config)
            || missing_required(&entry.descriptor.secret_material, &request.secret_material)
        {
            return Err(MintFailure::configuration("invalid mint request"));
        }
        let response = entry.implementation.mint(request).await?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
            .ok_or_else(MintFailure::invalid_response)?;
        if response.outputs.len() != entry.descriptor.outputs.len()
            || entry.descriptor.outputs.iter().any(|key| {
                response
                    .outputs
                    .get(key)
                    .is_none_or(|value| value.trim().is_empty())
            })
            || response.expiration_time_ms <= now_ms
            || response.rotated_secret_material.iter().any(|(key, value)| {
                !entry.descriptor.rotated_secret_material.contains(key) || value.trim().is_empty()
            })
        {
            return Err(MintFailure::invalid_response());
        }
        Ok(response)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn missing_required(fields: &[MaterialDescriptor], values: &HashMap<String, String>) -> bool {
    fields.iter().any(|field| {
        field.required
            && values
                .get(&field.name)
                .is_none_or(|value| value.trim().is_empty())
    })
}

fn valid_ids(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values
        .iter()
        .all(|value| valid_id(value) && seen.insert(value))
}

#[cfg(test)]
mod tests;
