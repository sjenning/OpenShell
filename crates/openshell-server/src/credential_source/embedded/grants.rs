// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Trusted gateway DTO projection for embedded issuer adoption. This module
//! never publishes providers, deletes legacy rows, or invokes a minter.

use crate::{
    credential_source::{
        DRIVER,
        handoff::{GrantPlan, StaticHandoff},
    },
    credentials::CredentialRuntime,
    persistence::{ObjectListQuery, Store},
    provider_refresh,
    storage_proto::StoredProviderCredentialRefreshStateV2 as LegacyState,
};
use openshell_core::{
    ObjectId as _, ObjectName as _, ObjectWorkspace as _,
    proto::{
        Provider, ProviderCredentialRefreshRecoveryAction as Action,
        ProviderCredentialRefreshStrategy as Strategy, credentials::store::v1 as wire,
    },
};
use openshell_credential_issuer::{
    SecretOwner,
    grant::GrantIdentity,
    minter::{RecoveryAction, StrategyDescriptor},
    remote_issuer::RemoteIssuer,
    repository::grants::{GrantPhase, OutputBinding, RetiredBacking},
    service::{
        CredentialRefreshService, CredentialStoreService, LegacyGrant, LegacyGrantOutput,
        LegacyGrantStatus,
    },
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use tonic::Status;

const ATTEMPT: &str = "openshell.nvidia.com/refresh-attempt";
const COMPLETED: &str = "openshell.nvidia.com/refresh-completed-mint";
type ProjectedMaterial = (BTreeMap<String, String>, BTreeMap<String, String>);

/// Import issuer metadata/configuration while preserving the old grant ID and
/// epoch. `refs` maps environment keys to already imported output references;
/// missing first-mint outputs receive durable value-free reservations and are
/// added to this map. The parent must atomically publish its provider handles,
/// value-free handoff, and deletion/sanitization of the exact legacy DTO revision
/// only after this returns, then acknowledge issuer activation. The parent owns
/// the legacy refresh and workspace mutation guards through that transaction;
/// this function must not reacquire them. No output value is read or copied here.
pub(super) async fn prepare(
    gateway: &Store,
    legacy: &CredentialRuntime,
    host: &CredentialStoreService,
    refresh: &CredentialRefreshService,
    provider: &Provider,
    state: &LegacyState,
    refs: &mut BTreeMap<String, String>,
) -> Result<Option<(GrantPlan, String, String)>, Status> {
    let metadata = state
        .metadata
        .as_ref()
        .ok_or_else(|| invalid("legacy refresh metadata missing"))?;
    if provider.object_id() != state.provider_id
        || provider.object_workspace() != state.object_workspace()
        || provider.object_name() != state.provider_name
        || metadata.resource_version == 0
        || state.credential_key.is_empty()
        || state.object_id().is_empty()
    {
        return Err(invalid("legacy refresh owner changed"));
    }
    let source = gateway
        .get("provider_credential_refresh_state", state.object_id())
        .await
        .map_err(|_| Status::unavailable("legacy refresh migration read failed"))?
        .ok_or_else(|| Status::aborted("legacy refresh disappeared during migration"))?;
    if source.resource_version != metadata.resource_version {
        return Err(Status::aborted("legacy refresh source generation changed"));
    }
    let live_provider = gateway
        .get("provider", provider.object_id())
        .await
        .map_err(|_| Status::unavailable("legacy provider migration read failed"))?
        .ok_or_else(|| Status::aborted("legacy provider disappeared during migration"))?;
    if live_provider.workspace != provider.object_workspace()
        || live_provider.name != provider.object_name()
    {
        return Err(Status::aborted("legacy provider identity changed"));
    }
    let strategy = Strategy::try_from(state.strategy)
        .map_err(|_| invalid("unknown legacy refresh strategy"))?;
    if matches!(
        strategy,
        Strategy::Static | Strategy::External | Strategy::Unspecified
    ) {
        // Such DTOs do not schedule minting. Never discard physical cleanup
        // ownership while the provider publication transaction is still pending.
        if !state.secret_material_handles.is_empty() || !state.pending_secret_deletions.is_empty() {
            return Err(invalid(
                "non-mintable legacy refresh still owns material cleanup",
            ));
        }
        return Ok(None);
    }
    let epoch = provider_refresh::effective_authorization_epoch(state)?.to_string();
    let strategy_name = provider_refresh::refresh_strategy_name(state.strategy);
    let registry = openshell_credential_issuer::builtins::registry();
    let descriptor = registry
        .describe()
        .find(|descriptor| descriptor.name == strategy_name)
        .cloned()
        .ok_or_else(|| invalid("legacy refresh strategy is unavailable"))?;
    let plan = plan(state, &descriptor, strategy)?;
    reject_published_authority(
        gateway,
        provider,
        state.object_id(),
        &plan.outputs.values().cloned().collect(),
    )
    .await?;
    let owner = SecretOwner {
        workspace: state.object_workspace().into(),
        provider_id: state.provider_id.clone(),
        credential_key: state.credential_key.clone(),
        ..Default::default()
    };
    host.embedded_scope()?.authorize_owner(&owner)?;
    let client = RemoteIssuer::embedded(host.clone(), refresh.clone()).await?;
    let mut outputs = BTreeMap::new();
    for (name, key) in &plan.outputs {
        let binding_owner = wire::SecretOwner {
            workspace: owner.workspace.clone(),
            provider_id: owner.provider_id.clone(),
            credential_key: key.clone(),
            ..Default::default()
        };
        let reference = if let Some(reference) = refs.get(key) {
            reference.clone()
        } else {
            if state.last_refresh_at_ms > 0 || state.status == "refreshed" {
                return Err(invalid("published legacy refresh output is missing"));
            }
            // The operation key is bounded even when immutable source strings
            // are long; it contains no values or secret-derived fingerprint.
            let bytes = serde_json::to_vec(&(state.object_id(), &epoch, key))
                .map_err(|_| invalid("legacy output identity encoding failed"))?;
            let digest = openshell_crypto::sha256(&bytes)
                .map_err(|_| Status::unavailable("legacy output identity unavailable"))?;
            let operation = format!("legacy-output:{}", hex(&digest));
            let reserved = client
                .reserve_secret(wire::ReserveSecretRequest {
                    owner: Some(binding_owner.clone()),
                    idempotency_key: operation,
                })
                .await?;
            refs.insert(key.clone(), reserved.reference.clone());
            reserved.reference
        };
        let observed = host
            .legacy_reference_state(&reference, &SecretOwner::from_wire(&binding_owner)?)
            .await?;
        outputs.insert(
            name.clone(),
            LegacyGrantOutput {
                binding: OutputBinding {
                    credential_key: key.clone(),
                    reference,
                },
                version: observed.version,
            },
        );
    }
    let mut material = state.material.clone();
    material.extend(
        legacy
            .resolve_refresh_material(
                provider_refresh::refresh_material_scope(state),
                &state.secret_material_handles,
            )
            .await?,
    );
    let (config, secrets) =
        project_material(state, &descriptor, material, plan.max_lifetime_seconds)?;
    let retired = retired_material(legacy, host, state, &owner, &epoch)?;
    let status = status(state)?;
    let id = refresh
        .replace_legacy_grant(LegacyGrant {
            identity: GrantIdentity {
                id: state.object_id().into(),
                authorization_epoch: epoch.clone(),
                owner,
            },
            source_revision: source.resource_version,
            source_provider_version: live_provider.resource_version,
            descriptor,
            outputs,
            config,
            secret_material: secrets,
            refresh_before_ms: i64::try_from(plan.refresh_before_ms)
                .map_err(|_| invalid("legacy refresh window exceeds range"))?,
            max_lifetime_seconds: i64::from(plan.max_lifetime_seconds),
            status,
            retired,
        })
        .await?;
    Ok(Some((plan, id, epoch)))
}

#[derive(serde::Deserialize)]
struct OwnershipKeyIndex {
    // The validated journal wire format is a map. This read-only serde
    // projection intentionally retains only its keys and discards all values.
    #[allow(clippy::zero_sized_map_values)]
    slots: BTreeMap<String, serde::de::IgnoredAny>,
}

/// The caller retains the same refresh/workspace locks as `prepare`. Abandon
/// dormant native copies BEFORE deleting the exact legacy cleanup owner.
pub(super) async fn abandon(
    gateway: &Store,
    refresh: &CredentialRefreshService,
    provider: &Provider,
    state: &LegacyState,
) -> Result<(), Status> {
    let metadata = state
        .metadata
        .as_ref()
        .ok_or_else(|| invalid("legacy refresh metadata missing"))?;
    if provider.object_id() != state.provider_id
        || provider.object_workspace() != state.object_workspace()
        || provider.object_name() != state.provider_name
        || metadata.resource_version == 0
        || state.credential_key.is_empty()
        || state.object_id().is_empty()
    {
        return Err(invalid("legacy refresh owner changed"));
    }
    let source = gateway
        .get("provider_credential_refresh_state", state.object_id())
        .await
        .map_err(|_| Status::unavailable("legacy refresh migration read failed"))?
        .ok_or_else(|| Status::aborted("legacy refresh disappeared during migration"))?;
    if source.resource_version != metadata.resource_version {
        return Err(Status::aborted("legacy refresh source generation changed"));
    }
    let mut outputs = state
        .additional_output_keys
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    outputs.insert(state.credential_key.clone());
    reject_published_authority(gateway, provider, state.object_id(), &outputs).await?;
    let owner = SecretOwner {
        workspace: state.object_workspace().into(),
        provider_id: state.provider_id.clone(),
        credential_key: state.credential_key.clone(),
        ..Default::default()
    };
    let identity = refresh
        .legacy_grant_import_identity(state.object_id(), &owner)
        .await?
        .unwrap_or(GrantIdentity {
            id: state.object_id().into(),
            authorization_epoch: provider_refresh::effective_authorization_epoch(state)?.into(),
            owner,
        });
    refresh.abandon_legacy_grant(identity).await
}

/// Retire a completed dormant import only after both the legacy DTO and all
/// publication authority are absent. Caller holds refresh/workspace guards.
pub(super) async fn abandon_orphan(
    gateway: &Store,
    refresh: &CredentialRefreshService,
    activation: &openshell_credential_issuer::service::LegacyGrantActivation,
) -> Result<(), Status> {
    if gateway
        .get("provider_credential_refresh_state", &activation.identity.id)
        .await
        .map_err(|_| Status::unavailable("legacy orphan proof read failed"))?
        .is_some()
    {
        return Ok(());
    }
    let owner = &activation.identity.owner;
    let provider = gateway
        .get_message::<Provider>(&owner.provider_id)
        .await
        .map_err(|_| Status::unavailable("legacy orphan provider read failed"))?
        .unwrap_or_else(|| Provider {
            metadata: Some(openshell_core::proto::ObjectMeta {
                id: owner.provider_id.clone(),
                workspace: owner.workspace.clone(),
                ..Default::default()
            }),
            ..Default::default()
        });
    if provider.object_id() != owner.provider_id || provider.object_workspace() != owner.workspace {
        return Err(invalid("legacy orphan provider identity changed"));
    }
    reject_published_authority(
        gateway,
        &provider,
        &activation.identity.id,
        &activation
            .outputs
            .values()
            .map(|output| output.credential_key.clone())
            .collect(),
    )
    .await?;
    refresh
        .abandon_legacy_grant(activation.identity.clone())
        .await
}

async fn reject_published_authority(
    gateway: &Store,
    provider: &Provider,
    grant: &str,
    outputs: &BTreeSet<String>,
) -> Result<(), Status> {
    // Inspect the ORIGINAL persisted provider, not the caller's in-memory
    // rewritten handles. Existing source authority must never become a reason
    // to fall back to a restored/stale legacy DTO, even for a static binding.
    if outputs.iter().any(|key| {
        provider
            .credential_handles
            .get(key)
            .is_some_and(|handle| handle.driver == DRIVER)
    }) {
        return Err(invalid(
            "legacy migration output already has issuer source authority",
        ));
    }
    let mut cursor = None;
    loop {
        let page = gateway
            .list_object_page(
                "credential_issuer_handoff_v1",
                ObjectListQuery::Workspace(provider.object_workspace()),
                cursor.as_ref(),
                128,
            )
            .await
            .map_err(|_| Status::unavailable("legacy publication proof read failed"))?;
        for row in page.records {
            // The public loader performs full canonical journal validation.
            // The narrow projection below reads only immutable output keys to
            // reject overlaps; it never grants ownership or bypasses validation.
            let Some(handoff) = StaticHandoff::load(gateway, &row.id).await? else {
                continue;
            };
            if handoff.provider_id() != provider.object_id()
                || !handoff.is_published()
                || handoff.grant_id().is_none()
            {
                continue;
            }
            let keys: OwnershipKeyIndex = serde_json::from_slice(&row.payload)
                .map_err(|_| invalid("legacy publication proof is malformed"))?;
            if handoff.grant_id() == Some(grant)
                || outputs.iter().any(|key| keys.slots.contains_key(key))
            {
                return Err(invalid(
                    "legacy migration conflicts with a published issuer grant",
                ));
            }
        }
        let Some(next) = page.next_cursor else {
            break;
        };
        cursor = Some(next);
    }
    Ok(())
}

fn project_material(
    state: &LegacyState,
    descriptor: &StrategyDescriptor,
    material: HashMap<String, String>,
    max_lifetime_seconds: u32,
) -> Result<ProjectedMaterial, Status> {
    let scopes = if state.scopes.is_empty() {
        provider_refresh::material_scopes(&material)
    } else {
        state.scopes.clone()
    };
    let mut config = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for (key, value) in material {
        // Legacy secret_material_keys selected protected physical storage, not
        // a minter's argument category. Both issuer categories are encrypted;
        // the pinned descriptor determines which category receives each field.
        if descriptor
            .secret_material
            .iter()
            .any(|field| field.name == key)
        {
            secrets.insert(key, value);
        } else if descriptor.config.iter().any(|field| field.name == key) {
            config.insert(key, value);
        } else if key != "scopes" {
            return Err(invalid("legacy material is not declared by its strategy"));
        }
    }
    // The legacy scopes alias is normalized only after resolving protected
    // material, so marking a recognized configuration field secret loses no
    // value or defaulting semantics.
    config.insert("token_url".into(), state.token_url.clone());
    config.insert("scope".into(), scopes.join(" "));
    config.insert(
        "max_lifetime_seconds".into(),
        max_lifetime_seconds.to_string(),
    );
    Ok((config, secrets))
}

fn plan(
    state: &LegacyState,
    descriptor: &StrategyDescriptor,
    strategy: Strategy,
) -> Result<GrantPlan, Status> {
    let primary = if strategy == Strategy::AwsStsAssumeRole {
        "access_key_id"
    } else {
        "access_token"
    };
    let mut outputs = state
        .additional_output_keys
        .iter()
        .map(|(name, key)| (name.clone(), key.clone()))
        .collect::<BTreeMap<_, _>>();
    if outputs
        .insert(primary.into(), state.credential_key.clone())
        .is_some()
        || outputs.keys().collect::<BTreeSet<_>>()
            != descriptor.outputs.iter().collect::<BTreeSet<_>>()
    {
        return Err(invalid("legacy refresh output bundle is incomplete"));
    }
    let before = duration(
        state.refresh_before.as_ref(),
        std::time::Duration::from_mins(5),
    )?;
    let lifetime = duration(
        state.max_lifetime.as_ref(),
        std::time::Duration::from_hours(1),
    )?;
    if lifetime.is_zero() || lifetime > std::time::Duration::from_hours(12) {
        return Err(invalid("legacy grant lifetime is invalid"));
    }
    let seconds = lifetime.as_secs() + u64::from(lifetime.subsec_nanos() != 0);
    let refresh_before_ms = u64::try_from(
        before.as_millis() + u128::from(!before.subsec_nanos().is_multiple_of(1_000_000)),
    )
    .map_err(|_| invalid("legacy refresh window exceeds range"))?;
    Ok(GrantPlan {
        credential_key: state.credential_key.clone(),
        strategy: descriptor.name.clone(),
        outputs,
        refresh_before_ms,
        max_lifetime_seconds: u32::try_from(seconds)
            .map_err(|_| invalid("legacy grant lifetime exceeds range"))?,
    })
}
fn duration(
    value: Option<&prost_types::Duration>,
    default: std::time::Duration,
) -> Result<std::time::Duration, Status> {
    value
        .map(openshell_core::time::duration_to_std)
        .transpose()
        .map_err(|_| invalid("legacy grant duration is invalid"))
        .map(|value| value.unwrap_or(default))
}
fn status(state: &LegacyState) -> Result<LegacyGrantStatus, Status> {
    let annotations = state
        .metadata
        .as_ref()
        .map(|metadata| &metadata.annotations);
    let attempt_id = annotations
        .and_then(|annotations| annotations.get(ATTEMPT))
        .filter(|value| !value.is_empty())
        .cloned();
    let completed_attempt = annotations
        .and_then(|annotations| annotations.get(COMPLETED))
        .filter(|value| !value.is_empty())
        .cloned();
    let classified_failure = match state.status.as_str() {
        "error" => Some((GrantPhase::Failed, RecoveryAction::Retry)),
        "configuration_required" => Some((GrantPhase::Failed, RecoveryAction::FixConfiguration)),
        "reauthorization_required" => Some((GrantPhase::Parked, RecoveryAction::Reauthorize)),
        "investigation_required" => Some((GrantPhase::Parked, RecoveryAction::Investigate)),
        _ => None,
    };
    let action = match Action::try_from(state.recovery_action) {
        Ok(Action::Unspecified) => classified_failure.map(|(_, action)| action),
        Ok(Action::Retry) => Some(RecoveryAction::Retry),
        Ok(Action::FixConfiguration) => Some(RecoveryAction::FixConfiguration),
        Ok(Action::Reauthorize) => Some(RecoveryAction::Reauthorize),
        Ok(Action::Investigate) | Err(_) => Some(RecoveryAction::Investigate),
    };
    let uncertain = matches!(
        state.status.as_str(),
        "refresh_in_progress" | "refresh_committing"
    ) || state.failure_code == "mint_outcome_unknown"
        || attempt_id.is_some()
            && completed_attempt != attempt_id
            && classified_failure.is_none()
            && !matches!(state.status.as_str(), "failed" | "parked");
    let phase = if state
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.deletion_time.is_some())
    {
        GrantPhase::Deleting
    } else if let Some((phase, _)) = classified_failure {
        phase
    } else {
        match state.status.as_str() {
            "configured" | "pending" | "rotation_requested" => GrantPhase::Pending,
            "refreshed" => GrantPhase::Refreshed,
            "failed" => GrantPhase::Failed,
            "parked" | "refresh_in_progress" | "refresh_committing" => GrantPhase::Parked,
            "deleting" => GrantPhase::Deleting,
            "deleted" => GrantPhase::Deleted,
            "detached" => GrantPhase::Detached,
            _ => return Err(invalid("legacy refresh status is unknown")),
        }
    };
    let completed_attempt = if phase == GrantPhase::Refreshed && completed_attempt.is_none() {
        // A pre-receipt legacy record already published its output bundle. This
        // deterministic historical marker is not an authorization to mint.
        Some(format!("legacy-completed:{}", state.object_id()))
    } else {
        completed_attempt
    };
    let subtype = openshell_credential_issuer::observability::recognized_provider_error_subtype(
        &state.failure_code,
        &state.provider_error_subtype,
    )
    .unwrap_or_default()
    .to_string();
    Ok(LegacyGrantStatus {
        version: state
            .metadata
            .as_ref()
            .map_or(1, |metadata| metadata.resource_version)
            .max(1),
        phase,
        expiration_time_ms: provider_refresh::refresh_has_expiration(state)
            .then_some(state.expires_at_ms),
        next_refresh_at_ms: if state.status == "rotation_requested" {
            0
        } else {
            state.next_refresh_at_ms
        },
        recovery_action: action,
        failure_code: state.failure_code.clone(),
        last_refresh_time_ms: (state.last_refresh_at_ms > 0).then_some(state.last_refresh_at_ms),
        last_error_time_ms: (state.last_error_at_ms > 0).then_some(state.last_error_at_ms),
        provider_error_subtype: subtype,
        attempt_id,
        completed_attempt,
        uncertain,
    })
}
fn retired_material(
    legacy: &CredentialRuntime,
    host: &CredentialStoreService,
    state: &LegacyState,
    owner: &SecretOwner,
    epoch: &str,
) -> Result<Vec<RetiredBacking>, Status> {
    let mut retired = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, handle) in state.secret_material_handles.iter().chain(
        state.pending_secret_deletions.iter().filter_map(|item| {
            item.handle
                .as_ref()
                .map(|handle| (&item.material_key, handle))
        }),
    ) {
        let purpose = format!("grant-material-v1:{}:{epoch}:{name}", state.object_id());
        let mut physical_key = b"openshell-refresh-material-credential-key-v1\0".to_vec();
        physical_key.extend_from_slice(state.credential_key.as_bytes());
        physical_key.push(0);
        physical_key.extend_from_slice(name.as_bytes());
        let digest = openshell_crypto::sha256(&physical_key)
            .map_err(|_| Status::unavailable("legacy material identity unavailable"))?;
        let physical_key = format!("openshell.refresh.{}", hex(&digest));
        let registration = if handle.driver.is_empty() {
            legacy.issuer_drivers().1
        } else {
            handle.driver.clone()
        };
        let backing = host.legacy_storage_backing(
            owner,
            &registration,
            &state.provider_name,
            &physical_key,
            &purpose,
            handle,
        )?;
        if seen.insert(backing.clone()) {
            retired.push(RetiredBacking {
                owner: owner.clone(),
                purpose,
                backing,
            });
        }
    }
    Ok(retired)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("writing String cannot fail");
    }
    result
}
fn invalid(message: &'static str) -> Status {
    Status::failed_precondition(message)
}

#[cfg(test)]
#[path = "grants_tests.rs"]
mod tests;
