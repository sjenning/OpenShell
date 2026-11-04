// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Trusted embedded grant adoption. This is not an RPC and never mints outputs.
//!
//! The secret-free source claim precedes every backend allocation. Candidate
//! records transfer cleanup ownership into a dormant import claim. Only an
//! explicit, Rust-only activation after gateway publication makes the grant
//! visible to scheduling and publishes output ownership plus the grant event.

use super::super::{CANDIDATE_KIND, Candidate, decode, encode, hex_digest};
use super::{CredentialRefreshService, OutputOwner, config_purpose, material_purpose};
use crate::{
    ReferenceStateStore as _,
    auth::GatewayScope,
    grant::GrantIdentity,
    minter::{RecoveryAction, StrategyDescriptor},
    repository::{
        Change, Mutation, ScopedRepository,
        grants::{
            self, GrantAttempt, GrantDefinition, GrantPhase, GrantState, OutputBinding,
            RetiredBacking,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tonic::{Request, Status};

const CLAIM_KIND: &str = "embedded-grant-import-v1";
const ABANDONED_KIND: &str = "embedded-grant-import-abandoned-v1";

impl super::CredentialStoreService {
    /// Trusted value-free migration inspection, including revoked references.
    ///
    /// Ordinary resolution still rejects tombstones. This Rust-only seam uses
    /// the same fixed embedded identity and complete immutable owner checks.
    pub async fn legacy_reference_state(
        &self,
        reference: &str,
        owner: &crate::SecretOwner,
    ) -> Result<crate::ReferenceState, Status> {
        let scope = self.embedded_scope()?;
        let state = self
            .runtime
            .repository
            .references(&scope)
            .load(reference)
            .await?
            .ok_or_else(|| Status::failed_precondition("legacy grant output was not imported"))?
            .state;
        scope.authorize_bound_owner(scope.identity(), &state.owner, owner)?;
        Ok(state)
    }
}

/// An already imported output. Values/physical handles are never copied here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyGrantOutput {
    pub binding: OutputBinding,
    pub version: u64,
}

/// Durable history and schedule projected from the legacy grant. In-flight or
/// explicitly uncertain phases are always parked, never automatically replayed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyGrantStatus {
    pub version: u64,
    pub phase: GrantPhase,
    pub expiration_time_ms: Option<i64>,
    pub next_refresh_at_ms: i64,
    pub recovery_action: Option<RecoveryAction>,
    pub failure_code: String,
    pub last_refresh_time_ms: Option<i64>,
    pub last_error_time_ms: Option<i64>,
    pub provider_error_subtype: String,
    pub attempt_id: Option<String>,
    pub completed_attempt: Option<String>,
    pub uncertain: bool,
}

/// Rust-only migration input.
///
/// No `Debug` implementation: configuration and material values must not escape
/// through diagnostics. Callers must retain the legacy DTO until issuer adoption
/// and provider handoff publication both commit.
#[derive(Clone)]
pub struct LegacyGrant {
    pub identity: GrantIdentity,
    pub source_revision: u64,
    /// Gateway publication CAS fence, not part of the native source intent.
    pub source_provider_version: u64,
    pub descriptor: StrategyDescriptor,
    pub outputs: BTreeMap<String, LegacyGrantOutput>,
    pub config: BTreeMap<String, String>,
    pub secret_material: BTreeMap<String, String>,
    pub refresh_before_ms: i64,
    pub max_lifetime_seconds: i64,
    pub status: LegacyGrantStatus,
    /// Already ownership-wrapped legacy material handles, never plaintext.
    pub retired: Vec<RetiredBacking>,
}

/// Secret-free recovery recipe.
///
/// The gateway must match the complete owner, authorization epoch, references,
/// and output keys to durable published
/// provider/journal records before acknowledging activation.
#[derive(Clone, Debug)]
pub struct LegacyGrantActivation {
    pub identity: GrantIdentity,
    pub outputs: BTreeMap<String, OutputBinding>,
}
#[derive(Clone, Debug)]
pub struct LegacyGrantActivationPage {
    pub grants: Vec<LegacyGrantActivation>,
    /// Last scanned import-claim key, including non-pending claims.
    pub after: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Staged {
    candidate: String,
    backing: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct Claim {
    // Hash of secret-free metadata only, not a credential fingerprint.
    intent: String,
    identity: GrantIdentity,
    // Persist before any allocation. Replacements must never recover candidates
    // from an older generation, including allocations journaled after replacement.
    // Only pre-generation claims may use the legacy grant-ID operation namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate_operation: Option<String>,
    started: Option<String>,
    staged: BTreeMap<String, Staged>,
    completed: bool,
    activated: bool,
    #[serde(default)]
    abandoned: bool,
    prepared: Option<GrantState>,
    output_versions: BTreeMap<String, u64>,
}
#[derive(Serialize)]
struct Intent<'a> {
    identity: &'a GrantIdentity,
    source_revision: u64,
    descriptor: &'a StrategyDescriptor,
    outputs: &'a BTreeMap<String, LegacyGrantOutput>,
    config_fields: Vec<&'a String>,
    material_fields: Vec<&'a String>,
    refresh_before_ms: i64,
    max_lifetime_seconds: i64,
    status: &'a LegacyGrantStatus,
    retired: &'a [RetiredBacking],
}

#[derive(Serialize, Deserialize)]
struct AbandonedClaim {
    /// Evidence of the old generation, including any unresolved allocation.
    /// Its legacy `retired` handles never become native cleanup candidates.
    claim: Claim,
    cleanup_candidates: Vec<String>,
}

struct Replacement {
    identity: GrantIdentity,
    intent: String,
}

impl Claim {
    fn pending(identity: GrantIdentity, intent: String) -> Self {
        Self {
            intent,
            candidate_operation: Some(format!(
                "legacy-grant:{}:{}",
                identity.id,
                uuid::Uuid::new_v4()
            )),
            identity,
            started: None,
            staged: BTreeMap::new(),
            completed: false,
            activated: false,
            abandoned: false,
            prepared: None,
            output_versions: BTreeMap::new(),
        }
    }
}

impl CredentialRefreshService {
    /// Replace only an unpublished, dormant legacy import generation.
    ///
    /// The trusted gateway must hold its source refresh/workspace locks and
    /// verify the current provider plus legacy DTO, with NO matching published
    /// grant handoff or grant-bearing provider binding. An existing current DTO
    /// under those locks proves the migration transaction did not commit when
    /// that transaction atomically deletes the exact DTO. This is not a
    /// publication rollback.
    /// Changed native copies transfer atomically to durable candidate cleanup;
    /// outputs and legacy-owned retired material are never touched. A native
    /// grant or an activated claim makes replacement fail, even for the same
    /// owner. An unchanged source intent resumes without allocating again.
    pub async fn replace_legacy_grant(&self, legacy: LegacyGrant) -> Result<String, Status> {
        self.validate_legacy_import(&legacy)?;
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        scope.authorize_owner(&legacy.identity.owner)?;
        let replacement = Replacement {
            identity: legacy.identity.clone(),
            intent: import_intent(&legacy)?,
        };
        self.abandon_dormant_generation(scope, legacy.identity.id.clone(), None, Some(replacement))
            .await?;
        self.import_legacy_grant(legacy).await
    }

    /// Abandon an unpublished import without revoking its output references.
    ///
    /// The gateway must prove publication never committed while holding the
    /// source refresh/workspace locks. The complete old identity fences this
    /// acknowledgment. Only native staged configuration/material are queued
    /// for cleanup; legacy DTO material remains owned by that DTO. A durable
    /// tombstone prevents a stale importer from silently recreating this claim.
    /// Use `replace_legacy_grant` to explicitly prepare a subsequent generation.
    pub async fn abandon_legacy_grant(&self, identity: GrantIdentity) -> Result<(), Status> {
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        scope.authorize_owner(&identity.owner)?;
        super::super::valid_reference(&identity.id)?;
        self.abandon_dormant_generation(scope, identity.id.clone(), Some(identity), None)
            .await
    }

    /// Read only an import's original identity, including partial imports. A
    /// current legacy tombstone can have a newer epoch than its dormant copies.
    /// The trusted gateway must retain its source locks and publication proof,
    /// then pass this exact identity to `abandon_legacy_grant`; this lookup does
    /// not authorize abandonment or relax its native-authority rejection.
    pub async fn legacy_grant_import_identity(
        &self,
        id: &str,
        owner: &crate::SecretOwner,
    ) -> Result<Option<GrantIdentity>, Status> {
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        scope.authorize_owner(owner)?;
        super::super::valid_reference(id)?;
        let store = self.runtime.store.repository.for_gateway(&scope);
        let Some(record) = store.load(CLAIM_KIND, id).await? else {
            return Ok(None);
        };
        let claim: Claim = decode(&record.payload)?;
        if claim.identity.id != id {
            return Err(Status::data_loss(
                "legacy import claim identity is inconsistent",
            ));
        }
        scope.authorize_bound_owner(scope.identity(), &claim.identity.owner, owner)?;
        Ok(Some(claim.identity))
    }

    async fn abandon_dormant_generation(
        &self,
        scope: GatewayScope,
        id: String,
        expected: Option<GrantIdentity>,
        replacement: Option<Replacement>,
    ) -> Result<(), Status> {
        let operation = format!("legacy-grant:{id}");
        let coordination = format!("{}:{operation}", scope.namespace());
        let runtime = self.runtime.clone();
        self.runtime
            .store
            .coordinator
            .run(&coordination, async move {
                let store = runtime.store.repository.for_gateway(&scope);
                let _operation_lease = store.acquire_refresh_lease(&operation).await?;
                let _grant_lease = store.acquire_refresh_lease(&format!("grant:{id}")).await?;
                if runtime
                    .store
                    .repository
                    .grants(&scope)
                    .load(&id)
                    .await?
                    .is_some()
                {
                    return Err(Status::failed_precondition(
                        "native legacy grant authority cannot be abandoned or replaced",
                    ));
                }
                let Some(record) = store.load(CLAIM_KIND, &id).await? else {
                    return Ok(());
                };
                let claim: Claim = decode(&record.payload)?;
                let candidate_operation =
                    claim.candidate_operation.as_deref().unwrap_or(&operation);
                let _candidate_guard = if candidate_operation == operation {
                    None
                } else {
                    Some(
                        runtime
                            .store
                            .coordinator
                            .lock_for(&format!("{}:{candidate_operation}", scope.namespace()))?
                            .lock_owned()
                            .await,
                    )
                };
                let _candidate_lease = if candidate_operation == operation {
                    None
                } else {
                    Some(store.acquire_refresh_lease(candidate_operation).await?)
                };
                scope.authorize_owner(&claim.identity.owner)?;
                if claim.identity.id != id {
                    return Err(Status::data_loss(
                        "legacy import claim identity is inconsistent",
                    ));
                }
                if claim.activated {
                    return Err(Status::failed_precondition(
                        "activated legacy grant cannot be abandoned or replaced",
                    ));
                }
                if expected
                    .as_ref()
                    .is_some_and(|identity| identity != &claim.identity)
                {
                    return Err(Status::permission_denied(
                        "legacy abandonment owner or epoch changed",
                    ));
                }
                if claim.abandoned {
                    if let Some(replacement) = replacement {
                        let next = Claim::pending(replacement.identity, replacement.intent);
                        save_claim(&store, &id, record.revision, &next).await?;
                    }
                    return Ok(());
                }
                if replacement.as_ref().is_some_and(|next| {
                    next.identity == claim.identity && next.intent == claim.intent
                }) {
                    return Ok(());
                }
                let archive_id = uuid::Uuid::new_v4().to_string();
                let cleanup_operation = format!("legacy-grant-cleanup:{archive_id}");
                let mut mutations = Vec::new();
                let mut cleanup_candidates = Vec::new();
                native_cleanup_candidates(
                    &store,
                    &claim,
                    candidate_operation,
                    &cleanup_operation,
                    &mut mutations,
                    &mut cleanup_candidates,
                )
                .await?;
                let next = if let Some(next) = replacement {
                    Claim::pending(next.identity, next.intent)
                } else {
                    let mut next = Claim::pending(claim.identity.clone(), claim.intent.clone());
                    next.abandoned = true;
                    next
                };
                // Preserve monotonically increasing claim revisions. Deleting and
                // recreating this row would let a stale activation pass an ABA CAS.
                mutations.push(Mutation::Put {
                    kind: CLAIM_KIND.into(),
                    key: id,
                    expected: Some(record.revision),
                    payload: encode(&next)?,
                });
                mutations.push(Mutation::Put {
                    kind: ABANDONED_KIND.into(),
                    key: archive_id,
                    expected: None,
                    payload: encode(&AbandonedClaim {
                        claim,
                        cleanup_candidates,
                    })?,
                });
                store.commit(&mutations, &[]).await?;
                Ok(())
            })
            .await
    }

    fn validate_legacy_import(&self, legacy: &LegacyGrant) -> Result<(), Status> {
        validate_input(legacy)?;
        let descriptor = self
            .runtime
            .minters
            .describe()
            .find(|value| value.name == legacy.descriptor.name)
            .ok_or_else(|| Status::failed_precondition("legacy grant strategy is unavailable"))?;
        if descriptor != &legacy.descriptor {
            return Err(Status::failed_precondition(
                "legacy grant strategy descriptor changed",
            ));
        }
        if !matches!(
            legacy.status.phase,
            GrantPhase::Deleted | GrantPhase::Detached
        ) {
            super::operations::validate_inputs(&descriptor.config, &legacy.config)?;
            super::operations::validate_inputs(
                &descriptor.secret_material,
                &legacy.secret_material,
            )?;
        }
        Ok(())
    }

    /// Enumerate dormant completed imports for startup recovery.
    ///
    /// Covers a crash between gateway publication and issuer activation. This
    /// exports only immutable non-secret metadata, never configuration or
    /// material backing.
    pub async fn pending_legacy_grants(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<LegacyGrantActivationPage, Status> {
        if !(1..=128).contains(&limit) {
            return Err(Status::invalid_argument(
                "legacy grant activation page limit is invalid",
            ));
        }
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        let page = self
            .runtime
            .store
            .repository
            .for_gateway(&scope)
            .list(
                CLAIM_KIND,
                after,
                u32::try_from(limit).expect("bounded activation page"),
            )
            .await?;
        let after =
            (page.len() == limit).then(|| page.last().expect("nonempty bounded page").0.clone());
        let mut grants = Vec::new();
        for (_, record) in page {
            let claim: Claim = decode(&record.payload)?;
            if claim.completed && !claim.activated && !claim.abandoned {
                let state = claim
                    .prepared
                    .ok_or_else(|| Status::data_loss("prepared legacy grant is missing"))?;
                if state.definition.identity != claim.identity {
                    return Err(Status::data_loss(
                        "legacy activation identity is inconsistent",
                    ));
                }
                scope.authorize_owner(&claim.identity.owner)?;
                grants.push(LegacyGrantActivation {
                    identity: claim.identity,
                    outputs: state.definition.outputs,
                });
            }
        }
        Ok(LegacyGrantActivationPage { grants, after })
    }

    /// Prepare an existing grant ID/authorization epoch and output versions.
    ///
    /// The durable prepared state is dormant: RPC lookup returns `NOT_FOUND` and
    /// no scheduler or cleanup worker can discover it until activation. This
    /// invokes no minter, allocates no output reference, and only admits the
    /// fixed local scope. Source generation/owner/epoch changes fail closed.
    pub async fn import_legacy_grant(&self, legacy: LegacyGrant) -> Result<String, Status> {
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        scope.authorize_owner(&legacy.identity.owner)?;
        self.validate_legacy_import(&legacy)?;
        let intent = import_intent(&legacy)?;
        let id = legacy.identity.id.clone();
        let operation = format!("legacy-grant:{id}");
        let coordination = format!("{}:{operation}", scope.namespace());
        let runtime = self.runtime.clone();
        self.runtime
            .store
            .coordinator
            .run(&coordination, async move {
                let store = runtime.store.repository.for_gateway(&scope);
                // The base operation serializes generations; the grant lease
                // excludes ordinary refresh/delete work after publication.
                let _operation_lease = store.acquire_refresh_lease(&operation).await?;
                let _grant_lease = store.acquire_refresh_lease(&format!("grant:{id}")).await?;
                let mut record = store.load(CLAIM_KIND, &id).await?;
                let mut claim = if let Some(record) = &record {
                    let claim: Claim = decode(&record.payload)?;
                    if claim.abandoned {
                        return Err(Status::failed_precondition(
                            "legacy grant import was abandoned; explicit replacement is required",
                        ));
                    }
                    if claim.intent != intent {
                        return Err(Status::aborted("legacy grant source generation changed"));
                    }
                    claim
                } else {
                    let claim = Claim::pending(legacy.identity.clone(), intent);
                    store
                        .commit(
                            &[Mutation::Put {
                                kind: CLAIM_KIND.into(),
                                key: id.clone(),
                                expected: None,
                                payload: encode(&claim)?,
                            }],
                            &[],
                        )
                        .await?;
                    record = store.load(CLAIM_KIND, &id).await?;
                    claim
                };
                let mut revision = record
                    .ok_or_else(|| Status::data_loss("legacy grant claim missing"))?
                    .revision;
                let candidate_operation = claim
                    .candidate_operation
                    .clone()
                    .unwrap_or_else(|| operation.clone());
                // Maintenance coordinates by candidate operation, not grant ID.
                // Retain its lease for the entire active generation operation.
                let _candidate_guard = if candidate_operation == operation {
                    None
                } else {
                    Some(
                        runtime
                            .store
                            .coordinator
                            .lock_for(&format!("{}:{candidate_operation}", scope.namespace()))?
                            .lock_owned()
                            .await,
                    )
                };
                let _candidate_lease = if candidate_operation == operation {
                    None
                } else {
                    Some(store.acquire_refresh_lease(&candidate_operation).await?)
                };
                if let Some(existing) = runtime.store.repository.grants(&scope).load(&id).await? {
                    verify_existing(&legacy, &existing.state)?;
                    if !claim.completed || !claim.activated {
                        return Err(Status::data_loss(
                            "legacy grant publication claim incomplete",
                        ));
                    }
                    return Ok(id);
                }
                if claim.completed {
                    if claim.activated {
                        return Err(Status::data_loss("imported legacy grant disappeared"));
                    }
                    verify_existing(
                        &legacy,
                        claim
                            .prepared
                            .as_ref()
                            .ok_or_else(|| Status::data_loss("prepared legacy grant is missing"))?,
                    )?;
                    return Ok(id);
                }
                let mut fences =
                    reference_fences(&runtime.store.repository, &scope, &legacy).await?;
                let mut state = imported_state(&legacy);
                let terminal = matches!(state.phase, GrantPhase::Deleted | GrantPhase::Detached);
                let mut shape = state.clone();
                shape.phase = if terminal {
                    GrantPhase::Reserved
                } else {
                    GrantPhase::Pending
                };
                shape.version = 1;
                shape.attempt = None;
                shape.completed_attempt = None;
                if terminal {
                    shape.expiration_time_ms = None;
                    shape.next_refresh_at_ms = i64::MAX;
                } else {
                    shape.definition.config_backing = vec![1];
                    shape.material = legacy
                        .secret_material
                        .keys()
                        .map(|name| (name.clone(), vec![1]))
                        .collect();
                }
                // Validate the same repository shape/history constraints before
                // touching a backend. These sentinels are never persisted.
                runtime
                    .store
                    .repository
                    .grants(&scope)
                    .prepare(None, &shape)
                    .await?;
                // Recovery first attaches a durably journaled candidate to its
                // pre-allocation claim. An unknown backend allocation is NOT retried.
                if let Some(purpose) = claim.started.clone() {
                    let staged = recover_candidate(&store, &candidate_operation, &purpose).await?;
                    claim.staged.insert(purpose, staged);
                    claim.started = None;
                    revision = save_claim(&store, &id, revision, &claim).await?;
                }
                let mut cleaned = Vec::new();
                for (purpose, staged) in &claim.staged {
                    match store.load(CANDIDATE_KIND, &staged.candidate).await? {
                        None => cleaned.push(purpose.clone()),
                        Some(record) => {
                            let candidate: Candidate = decode(&record.payload)?;
                            if record.revision != 1 {
                                return Err(Status::unavailable(
                                    "legacy candidate cleanup is in progress",
                                ));
                            }
                            if candidate.owner != legacy.identity.owner
                                || candidate.purpose != *purpose
                                || candidate.operation_key != candidate_operation
                                || candidate.backing != staged.backing
                            {
                                return Err(Status::data_loss(
                                    "legacy candidate ownership changed",
                                ));
                            }
                        }
                    }
                }
                if !cleaned.is_empty() {
                    // Maintenance removes a candidate record only after backend
                    // deletion succeeds. A completed cleanup may be safely restaged.
                    for purpose in cleaned {
                        claim.staged.remove(&purpose);
                    }
                    revision = save_claim(&store, &id, revision, &claim).await?;
                }
                let mut values = BTreeMap::new();
                if !terminal {
                    values.insert(
                        config_purpose(&state),
                        String::from_utf8(encode(&legacy.config)?)
                            .map_err(|_| Status::internal("legacy config encoding failed"))?,
                    );
                    for (name, value) in legacy.secret_material {
                        values.insert(material_purpose(&state, &name), value);
                    }
                }
                for (purpose, value) in values {
                    if claim.staged.contains_key(&purpose) {
                        continue;
                    }
                    // Persist intent before stage_candidate can invoke a driver.
                    claim.started = Some(purpose.clone());
                    revision = save_claim(&store, &id, revision, &claim).await?;
                    let (candidate, backing) = runtime
                        .store
                        .stage_candidate(
                            &scope,
                            &legacy.identity.owner,
                            &candidate_operation,
                            &purpose,
                            value,
                        )
                        .await?;
                    claim.staged.insert(purpose, Staged { candidate, backing });
                    claim.started = None;
                    revision = save_claim(&store, &id, revision, &claim).await?;
                }
                if !terminal {
                    state.definition.config_backing = claim
                        .staged
                        .get(&config_purpose(&state))
                        .ok_or_else(|| Status::data_loss("legacy config candidate missing"))?
                        .backing
                        .clone();
                }
                for field in &state.definition.descriptor.secret_material {
                    if let Some(staged) = claim.staged.get(&material_purpose(&state, &field.name)) {
                        state
                            .material
                            .insert(field.name.clone(), staged.backing.clone());
                    }
                }
                // Reuse the repository's full shape/material/history validator via
                // a new-pending projection. The trusted import alone may retain a
                // historical version/phase instead of inventing a fresh epoch.
                let mut projection = state.clone();
                projection.phase = if terminal {
                    GrantPhase::Reserved
                } else {
                    GrantPhase::Pending
                };
                projection.version = 1;
                projection.attempt = None;
                projection.completed_attempt = None;
                if terminal {
                    projection.expiration_time_ms = None;
                    projection.next_refresh_at_ms = i64::MAX;
                }
                runtime
                    .store
                    .repository
                    .grants(&scope)
                    .prepare(None, &projection)
                    .await?;
                let mut mutations = Vec::new();
                mutations.append(&mut fences);
                for staged in claim.staged.values() {
                    mutations.push(Mutation::Delete {
                        kind: CANDIDATE_KIND.into(),
                        key: staged.candidate.clone(),
                        expected: 1,
                    });
                }
                // Transfer candidate cleanup ownership into the durable import
                // claim, NOT the scheduler-visible grant table. Another replica
                // cannot mint or delete retired legacy handles before the
                // gateway's provider/handoff/DTO publication transaction commits.
                claim.completed = true;
                claim.output_versions = legacy
                    .outputs
                    .iter()
                    .map(|(name, output)| (name.clone(), output.version))
                    .collect();
                claim.prepared = Some(state);
                mutations.push(Mutation::Put {
                    kind: CLAIM_KIND.into(),
                    key: id.clone(),
                    expected: Some(revision),
                    payload: encode(&claim)?,
                });
                store.commit(&mutations, &[]).await?;
                Ok(id)
            })
            .await
    }

    /// Activate a prepared grant after durable gateway publication.
    ///
    /// Activate ONLY after the gateway atomically publishes matching issuer
    /// handles and the value-free ownership journal while removing/sanitizing
    /// the exact legacy DTO revision. On restart, the host must verify that
    /// durable publication proof before calling this Rust-only API again.
    /// Identity is a full immutable owner/epoch fence, not merely a grant ID.
    /// Neither a lookup, watch subscription, nor a background sweep activates
    /// an import. Repeated activation never resets an already-live grant.
    pub async fn activate_legacy_grant(&self, identity: GrantIdentity) -> Result<(), Status> {
        let scope = self
            .runtime
            .store
            .policy
            .authenticate(&crate::auth::local_request(Request::new(())))?;
        scope.authorize_owner(&identity.owner)?;
        super::super::valid_reference(&identity.id)?;
        let operation = format!("legacy-grant:{}", identity.id);
        let coordination = format!("{}:{operation}", scope.namespace());
        let runtime = self.runtime.clone();
        self.runtime
            .store
            .coordinator
            .run(&coordination, async move {
                let store = runtime.store.repository.for_gateway(&scope);
                let _operation_lease = store.acquire_refresh_lease(&operation).await?;
                let _grant_lease = store
                    .acquire_refresh_lease(&format!("grant:{}", identity.id))
                    .await?;
                let record = store.load(CLAIM_KIND, &identity.id).await?.ok_or_else(|| {
                    Status::failed_precondition("legacy grant import claim is missing")
                })?;
                let mut claim: Claim = decode(&record.payload)?;
                if claim.identity != identity {
                    return Err(Status::permission_denied(
                        "legacy grant activation owner or epoch changed",
                    ));
                }
                if claim.abandoned || !claim.completed {
                    return Err(Status::failed_precondition(
                        "legacy grant import is not prepared",
                    ));
                }
                let existing = runtime
                    .store
                    .repository
                    .grants(&scope)
                    .load(&identity.id)
                    .await?;
                if claim.activated {
                    let existing = existing
                        .ok_or_else(|| Status::data_loss("activated legacy grant disappeared"))?;
                    if existing.state.definition.identity != identity {
                        return Err(Status::permission_denied(
                            "activated legacy grant owner or epoch changed",
                        ));
                    }
                    return Ok(());
                }
                if existing.is_some() {
                    return Err(Status::already_exists(
                        "legacy grant activation identity is already occupied",
                    ));
                }
                let state = claim
                    .prepared
                    .take()
                    .ok_or_else(|| Status::data_loss("prepared legacy grant is missing"))?;
                if state.definition.identity != identity
                    || state
                        .definition
                        .outputs
                        .keys()
                        .ne(claim.output_versions.keys())
                {
                    return Err(Status::data_loss(
                        "prepared legacy activation metadata is invalid",
                    ));
                }
                let refs = runtime.store.repository.references(&scope);
                let mut mutations = Vec::new();
                for (name, output) in &state.definition.outputs {
                    let current = refs.load(&output.reference).await?.ok_or_else(|| {
                        Status::failed_precondition("legacy activation output is missing")
                    })?;
                    let mut owner = identity.owner.clone();
                    owner.credential_key.clone_from(&output.credential_key);
                    scope.authorize_bound_owner(scope.identity(), &current.state.owner, &owner)?;
                    if current.state.version != claim.output_versions[name] {
                        return Err(Status::aborted(
                            "legacy output version changed before activation",
                        ));
                    }
                    mutations.push(Mutation::Check {
                        kind: crate::repository::references::KIND.into(),
                        key: output.reference.clone(),
                        expected: current.revision,
                    });
                    if !matches!(state.phase, GrantPhase::Deleted | GrantPhase::Detached) {
                        if let Some(record) = store
                            .load(grants::OUTPUT_BINDING_KIND, &output.reference)
                            .await?
                        {
                            let bound: OutputOwner = decode(&record.payload)?;
                            if (&bound.grant, &bound.authorization_epoch)
                                != (&identity.id, &identity.authorization_epoch)
                            {
                                return Err(Status::permission_denied(
                                    "legacy activation output belongs to another grant",
                                ));
                            }
                            mutations.push(Mutation::Check {
                                kind: grants::OUTPUT_BINDING_KIND.into(),
                                key: output.reference.clone(),
                                expected: record.revision,
                            });
                        } else {
                            mutations.push(Mutation::Put {
                                kind: grants::OUTPUT_BINDING_KIND.into(),
                                key: output.reference.clone(),
                                expected: None,
                                payload: encode(&OutputOwner {
                                    grant: identity.id.clone(),
                                    authorization_epoch: identity.authorization_epoch.clone(),
                                })?,
                            });
                        }
                    }
                }
                mutations.push(Mutation::Put {
                    kind: grants::KIND.into(),
                    key: identity.id.clone(),
                    expected: None,
                    payload: encode(&state)?,
                });
                claim.activated = true;
                claim.staged.clear();
                mutations.push(Mutation::Put {
                    kind: CLAIM_KIND.into(),
                    key: identity.id.clone(),
                    expected: Some(record.revision),
                    payload: encode(&claim)?,
                });
                store
                    .commit(
                        &mutations,
                        &[Change {
                            kind: "grant".into(),
                            key: identity.id,
                            version: state.version,
                            deleted: matches!(
                                state.phase,
                                GrantPhase::Deleted | GrantPhase::Detached
                            ),
                        }],
                    )
                    .await?;
                Ok(())
            })
            .await
    }
}

fn import_intent(legacy: &LegacyGrant) -> Result<String, Status> {
    // Provider metadata revisions are fenced by the gateway transaction, not
    // by ownership of an otherwise identical import. The legacy DTO revision,
    // output identities/versions, and complete recipe still bind this intent.
    hex_digest(&encode(&Intent {
        identity: &legacy.identity,
        source_revision: legacy.source_revision,
        descriptor: &legacy.descriptor,
        outputs: &legacy.outputs,
        config_fields: legacy.config.keys().collect(),
        material_fields: legacy.secret_material.keys().collect(),
        refresh_before_ms: legacy.refresh_before_ms,
        max_lifetime_seconds: legacy.max_lifetime_seconds,
        status: &legacy.status,
        retired: &legacy.retired,
    })?)
}

async fn native_cleanup_candidates(
    store: &ScopedRepository,
    claim: &Claim,
    operation: &str,
    cleanup_operation: &str,
    mutations: &mut Vec<Mutation>,
    cleanup_candidates: &mut Vec<String>,
) -> Result<(), Status> {
    if let Some(prepared) = &claim.prepared {
        if prepared.definition.identity != claim.identity {
            return Err(Status::data_loss(
                "dormant legacy grant identity is inconsistent",
            ));
        }
        if !prepared.definition.config_backing.is_empty()
            && claim
                .staged
                .get(&config_purpose(prepared))
                .is_none_or(|staged| staged.backing != prepared.definition.config_backing)
        {
            return Err(Status::data_loss(
                "dormant configuration lost its native candidate ownership",
            ));
        }
        for (name, backing) in &prepared.material {
            if claim
                .staged
                .get(&material_purpose(prepared, name))
                .is_none_or(|staged| &staged.backing != backing)
            {
                return Err(Status::data_loss(
                    "dormant material lost its native candidate ownership",
                ));
            }
        }
        // Deliberately do not traverse prepared.retired or its output bindings:
        // those are still legacy-owned until gateway publication + activation.
    }
    let config = format!(
        "grant-config-v1:{}:{}",
        claim.identity.id, claim.identity.authorization_epoch
    );
    let material = format!(
        "grant-material-v1:{}:{}:",
        claim.identity.id, claim.identity.authorization_epoch
    );
    for (purpose, staged) in &claim.staged {
        if staged.backing.is_empty()
            || (purpose != &config
                && !purpose
                    .strip_prefix(material.as_str())
                    .is_some_and(crate::minter::valid_id))
        {
            return Err(Status::data_loss(
                "invalid dormant native candidate purpose",
            ));
        }
        if let Some(record) = store.load(CANDIDATE_KIND, &staged.candidate).await? {
            let candidate: Candidate = decode(&record.payload)?;
            if (
                &candidate.owner,
                candidate.operation_key.as_str(),
                &candidate.purpose,
                &candidate.backing,
            ) != (&claim.identity.owner, operation, purpose, &staged.backing)
            {
                return Err(Status::data_loss(
                    "dormant native candidate ownership changed",
                ));
            }
            // Existing candidates already retain cleanup ownership, including
            // one a maintenance worker has claimed at a later revision.
            mutations.push(Mutation::Check {
                kind: CANDIDATE_KIND.into(),
                key: staged.candidate.clone(),
                expected: record.revision,
            });
            cleanup_candidates.push(staged.candidate.clone());
        } else {
            // A completed preparation transferred this backing out of the
            // candidate table. Requeue a NEW cleanup identity atomically with
            // abandonment; never revive a candidate key a late writer knows.
            let key = uuid::Uuid::new_v4().to_string();
            let candidate = Candidate {
                operation_key: cleanup_operation.into(),
                owner: claim.identity.owner.clone(),
                purpose: purpose.clone(),
                backing: staged.backing.clone(),
            };
            mutations.push(Mutation::Put {
                kind: CANDIDATE_KIND.into(),
                key: key.clone(),
                expected: None,
                payload: encode(&candidate)?,
            });
            cleanup_candidates.push(key);
        }
    }
    // A started allocation not yet attached to claim.staged remains in its
    // existing candidate journal, if one committed. Otherwise the archive keeps
    // the unresolved operation marker; abandonment never erases that evidence.
    Ok(())
}

fn validate_input(legacy: &LegacyGrant) -> Result<(), Status> {
    super::super::valid_reference(&legacy.identity.id)?;
    super::super::valid_reference(&legacy.identity.authorization_epoch)?;
    let names = legacy.descriptor.outputs.iter().collect::<BTreeSet<_>>();
    if legacy.source_revision == 0
        || legacy.source_provider_version == 0
        || legacy.status.version == 0
        || legacy.refresh_before_ms < 0
        // Only this trusted Rust-only upgrade seam admits the old positive
        // protobuf duration contract. Create/reserve RPC admission stays capped
        // at twelve hours; importing must not silently shorten an old grant.
        || !(1..=openshell_core::time::MAX_DURATION_SECONDS + 1)
            .contains(&legacy.max_lifetime_seconds)
        || legacy.refresh_before_ms > openshell_core::time::MAX_DURATION_SECONDS * 1000 + 1000
        || legacy.outputs.is_empty()
        || legacy.outputs.len() > 64
        || legacy.outputs.keys().collect::<BTreeSet<_>>() != names
        || legacy.outputs.values().any(|output| output.version == 0)
        || legacy
            .outputs
            .values()
            .map(|output| &output.binding.reference)
            .collect::<BTreeSet<_>>()
            .len()
            != legacy.outputs.len()
        || legacy
            .outputs
            .values()
            .map(|output| &output.binding.credential_key)
            .collect::<BTreeSet<_>>()
            .len()
            != legacy.outputs.len()
        || legacy.status.phase == GrantPhase::Reserved
        || legacy.status.phase == GrantPhase::Refreshed
            && legacy
                .status
                .completed_attempt
                .as_ref()
                .is_none_or(String::is_empty)
        || legacy
            .status
            .expiration_time_ms
            .is_some_and(|time| time <= 0)
        || legacy
            .status
            .attempt_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256 || id.chars().any(char::is_control))
        || legacy
            .config
            .iter()
            .chain(&legacy.secret_material)
            .try_fold(0usize, |size, (key, value)| {
                size.checked_add(key.len())?.checked_add(value.len())
            })
            .is_none_or(|size| size > super::super::MESSAGE_LIMIT)
        || legacy.retired.iter().any(|value| value.backing.is_empty())
    {
        return Err(Status::invalid_argument("invalid legacy grant migration"));
    }
    for output in legacy.outputs.values() {
        super::super::valid_reference(&output.binding.reference)?;
        if output.binding.credential_key.is_empty() {
            return Err(Status::invalid_argument("legacy output key is empty"));
        }
    }
    Ok(())
}

fn imported_state(legacy: &LegacyGrant) -> GrantState {
    let uncertain = !matches!(
        legacy.status.phase,
        GrantPhase::Deleting | GrantPhase::Deleted | GrantPhase::Detached
    ) && (legacy.status.uncertain
        || matches!(
            legacy.status.phase,
            GrantPhase::Refreshing | GrantPhase::Publishing
        ));
    let parked = uncertain || legacy.status.phase == GrantPhase::Parked;
    let mut state = GrantState {
        format_version: 1,
        definition: GrantDefinition {
            identity: legacy.identity.clone(),
            descriptor: legacy.descriptor.clone(),
            config_backing: Vec::new(),
            outputs: legacy
                .outputs
                .iter()
                .map(|(name, output)| (name.clone(), output.binding.clone()))
                .collect(),
            refresh_before_ms: legacy.refresh_before_ms,
            max_lifetime_seconds: legacy.max_lifetime_seconds,
        },
        material: BTreeMap::new(),
        version: legacy.status.version,
        phase: if parked {
            GrantPhase::Parked
        } else {
            legacy.status.phase
        },
        expiration_time_ms: legacy.status.expiration_time_ms,
        next_refresh_at_ms: if parked {
            i64::MAX
        } else {
            legacy.status.next_refresh_at_ms
        },
        recovery_action: if uncertain {
            Some(RecoveryAction::Investigate)
        } else {
            legacy.status.recovery_action
        },
        failure_code: if uncertain {
            "mint_outcome_unknown".into()
        } else {
            legacy.status.failure_code.clone()
        },
        last_refresh_time_ms: legacy.status.last_refresh_time_ms,
        last_error_time_ms: legacy.status.last_error_time_ms,
        provider_error_subtype: if uncertain {
            String::new()
        } else {
            legacy.status.provider_error_subtype.clone()
        },
        attempt: None,
        completed_attempt: legacy.status.completed_attempt.clone(),
        retired: legacy.retired.clone(),
    };
    if parked {
        if !matches!(
            state.recovery_action,
            Some(RecoveryAction::Investigate | RecoveryAction::Reauthorize)
        ) {
            state.recovery_action = Some(RecoveryAction::Investigate);
        }
        if let Some(id) = &legacy.status.attempt_id {
            state.attempt = Some(GrantAttempt {
                id: id.clone(),
                encrypted_result: None,
                expected_output_versions: legacy
                    .outputs
                    .iter()
                    .map(|(name, output)| (name.clone(), output.version))
                    .collect(),
                output_candidates: BTreeMap::new(),
                material_candidates: BTreeMap::new(),
                rotation_receipt: None,
            });
        }
    }
    if matches!(state.phase, GrantPhase::Deleted | GrantPhase::Detached) {
        state.next_refresh_at_ms = i64::MAX;
        state.recovery_action = None;
        state.failure_code.clear();
        state.provider_error_subtype.clear();
    }
    state
}

fn verify_existing(legacy: &LegacyGrant, state: &GrantState) -> Result<(), Status> {
    if state.definition.identity != legacy.identity
        || state.definition.descriptor != legacy.descriptor
        || state.definition.outputs
            != legacy
                .outputs
                .iter()
                .map(|(name, output)| (name.clone(), output.binding.clone()))
                .collect()
    {
        return Err(Status::permission_denied(
            "legacy grant owner or authorization epoch changed",
        ));
    }
    Ok(())
}

async fn reference_fences(
    repository: &std::sync::Arc<crate::repository::Repository>,
    scope: &GatewayScope,
    legacy: &LegacyGrant,
) -> Result<Vec<Mutation>, Status> {
    let refs = repository.references(scope);
    let mut fences = Vec::new();
    for output in legacy.outputs.values() {
        let record = refs
            .load(&output.binding.reference)
            .await?
            .ok_or_else(|| Status::failed_precondition("legacy grant output was not imported"))?;
        let mut owner = legacy.identity.owner.clone();
        owner
            .credential_key
            .clone_from(&output.binding.credential_key);
        scope.authorize_bound_owner(scope.identity(), &record.state.owner, &owner)?;
        if record.state.version != output.version {
            return Err(Status::aborted("legacy grant output version changed"));
        }
        fences.push(Mutation::Check {
            kind: crate::repository::references::KIND.into(),
            key: output.binding.reference.clone(),
            expected: record.revision,
        });
    }
    Ok(fences)
}
async fn save_claim(
    store: &ScopedRepository,
    id: &str,
    revision: u64,
    claim: &Claim,
) -> Result<u64, Status> {
    let receipt = store
        .commit(
            &[Mutation::Put {
                kind: CLAIM_KIND.into(),
                key: id.into(),
                expected: Some(revision),
                payload: encode(claim)?,
            }],
            &[],
        )
        .await?;
    Ok(receipt.revisions[&(CLAIM_KIND.into(), id.into())])
}
async fn recover_candidate(
    store: &ScopedRepository,
    operation: &str,
    purpose: &str,
) -> Result<Staged, Status> {
    let mut after = None;
    let mut recovered = None;
    loop {
        let page = store.list(CANDIDATE_KIND, after.as_deref(), 128).await?;
        if page.is_empty() {
            break;
        }
        for (key, record) in page {
            after = Some(key.clone());
            let candidate: Candidate = decode(&record.payload)?;
            if candidate.operation_key == operation && candidate.purpose == purpose {
                if record.revision != 1 || recovered.is_some() {
                    return Err(Status::failed_precondition(
                        "legacy candidate cleanup or allocation is unresolved",
                    ));
                }
                recovered = Some(Staged {
                    candidate: key,
                    backing: candidate.backing,
                });
            }
        }
    }
    recovered.ok_or_else(|| {
        Status::failed_precondition(
            "legacy backend allocation outcome is unknown; automatic replay is unsafe",
        )
    })
}

#[cfg(test)]
#[path = "migration_grants_tests.rs"]
mod tests;
