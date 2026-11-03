// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Atomic admission and reclaimable terminal bindings. Active bindings are never evicted.
use super::{
    GRANTS, Grant, Inner, REFERENCES, Secret, State, WatchHealth, refresh, same_owner, store,
    validation,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tonic::Status;

/// One successful value-free intent per tracked binding, never a lifetime
/// idempotency cache. Reclamation drops its receipt and incarnation tokens.
pub(super) struct GrantReservation {
    intent: [u8; 32],
    outputs: BTreeMap<String, (String, Arc<()>)>,
}
enum Reservation {
    Secret([u8; 32]),
    Grant([u8; 32], HashMap<String, String>),
}

pub(super) fn owner(mut owner: store::SecretOwner) -> Result<store::SecretOwner, Status> {
    if !validation::id(&owner.workspace)
        || !validation::id(&owner.provider_id)
        || !validation::id(&owner.credential_key)
    {
        return Err(Status::invalid_argument("invalid issuer reference binding"));
    }
    // Display names are audit-only and must not inflate retained bindings.
    owner.provider = String::new();
    Ok(owner)
}

pub(super) struct Observation {
    pub health: WatchHealth,
    pub value_generation: u64,
    pub metadata_generation: u64,
    bindings: BTreeMap<String, Arc<()>>,
}
impl Observation {
    pub fn secret_matches(&self, reference: &str, entry: &Secret) -> bool {
        self.bindings
            .get(reference)
            .is_some_and(|binding| Arc::ptr_eq(binding, &entry.binding))
    }
    pub fn grant_matches(&self, grant: &str, entry: &Grant) -> bool {
        self.bindings
            .get(grant)
            .is_some_and(|binding| Arc::ptr_eq(binding, &entry.binding))
    }
}

impl State {
    fn capacity(&mut self, secrets: usize, grants: usize) -> Result<(), Status> {
        // Tombstones provide local NotFound while space permits, but do not
        // consume a lifetime quota. A new registration of an evicted binding
        // starts unknown and must authenticate/reconcile again. In-flight
        // observations hold identity tokens, not authorization to restore it.
        if self.secrets.len() + self.reserved_secrets + secrets > REFERENCES {
            self.secrets
                .retain(|_, entry| !entry.gone || entry.admissions > 0);
        }
        if self.grants.len() + self.reserved_grants + grants > GRANTS {
            self.grants
                .retain(|_, entry| !entry.gone || entry.admissions > 0);
        }
        self.check_capacity(secrets, grants)
    }
    fn check_capacity(&self, secrets: usize, grants: usize) -> Result<(), Status> {
        if self.secrets.len() + self.reserved_secrets + secrets > REFERENCES
            || self.grants.len() + self.reserved_grants + grants > GRANTS
        {
            return Err(Status::resource_exhausted(
                "issuer tracked binding limit reached",
            ));
        }
        Ok(())
    }
    fn insert(
        &mut self,
        secrets: Vec<(String, store::SecretOwner)>,
        grants: Vec<String>,
    ) -> Result<(), Status> {
        // Validate the complete bundle before changing any ownership metadata.
        let mut owners = BTreeMap::new();
        for (reference, owner) in &secrets {
            if !validation::id(reference) {
                return Err(Status::invalid_argument("invalid issuer reference binding"));
            }
            if self
                .secrets
                .get(reference)
                .is_some_and(|old| !same_owner(owner, &old.owner))
                || owners
                    .insert(reference.clone(), owner)
                    .is_some_and(|old| !same_owner(owner, old))
            {
                return Err(Status::failed_precondition(
                    "issuer reference owner changed",
                ));
            }
        }
        if grants.iter().any(|grant| !validation::id(grant)) {
            return Err(Status::invalid_argument("invalid issuer grant binding"));
        }
        let new_secrets = owners
            .keys()
            .filter(|id| !self.secrets.contains_key(*id))
            .count();
        let new_grants = grants
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|id| !self.grants.contains_key(*id))
            .count();
        // Keep requested tombstones: dropping one here would both erase its
        // revocation fence and undercount the capacity needed to reinsert it.
        if self.secrets.len() + self.reserved_secrets + new_secrets > REFERENCES {
            self.secrets
                .retain(|id, entry| !entry.gone || entry.admissions > 0 || owners.contains_key(id));
        }
        if self.grants.len() + self.reserved_grants + new_grants > GRANTS {
            self.grants
                .retain(|id, entry| !entry.gone || entry.admissions > 0 || grants.contains(id));
        }
        self.check_capacity(new_secrets, new_grants)?;
        if new_secrets > 0 {
            self.secrets_reconciled = false;
        }
        if new_grants > 0 {
            self.grants_reconciled = false;
        }
        for (reference, owner) in secrets {
            self.secrets.entry(reference).or_insert_with(|| Secret {
                owner,
                metadata: None,
                version: 0,
                gone: false,
                terminal: false,
                binding: Arc::new(()),
                reservation: None,
                admissions: 0,
            });
        }
        for grant in grants {
            self.grants.entry(grant).or_insert_with(|| Grant {
                metadata: None,
                version: 0,
                gone: false,
                terminal: false,
                binding: Arc::new(()),
                reservation: None,
                admissions: 0,
            });
        }
        Ok(())
    }
    pub fn secret_observation(&self, references: impl Iterator<Item = String>) -> Observation {
        Observation {
            health: self.health,
            value_generation: self.value_generation,
            metadata_generation: self.secret_generation,
            bindings: references
                .filter_map(|id| {
                    self.secrets
                        .get(&id)
                        .map(|entry| (id, entry.binding.clone()))
                })
                .collect(),
        }
    }
    pub fn grant_observation(&self, grants: impl Iterator<Item = String>) -> Observation {
        Observation {
            health: self.health,
            value_generation: self.value_generation,
            metadata_generation: self.grant_generation,
            bindings: grants
                .filter_map(|id| {
                    self.grants
                        .get(&id)
                        .map(|entry| (id, entry.binding.clone()))
                })
                .collect(),
        }
    }
    pub fn retire_secret(&mut self, reference: &str, version: u64) {
        // The terminal bit and incarnation token fence in-flight operations on
        // this binding. Do not invalidate unrelated reconciliation candidates.
        self.values.retain(|(id, _), _| id != reference);
        self.bytes = self
            .values
            .values()
            .map(|value| value.value.value.len())
            .sum();
        if let Some(entry) = self.secrets.get_mut(reference) {
            entry.version = entry.version.max(version);
            entry.gone = true;
            entry.terminal = true;
            entry.metadata = None;
            self.secrets_reconciled = false;
        }
    }
    pub fn retire_grant(&mut self, grant: &str, version: u64) {
        if let Some(entry) = self.grants.get_mut(grant) {
            entry.version = entry.version.max(version);
            entry.gone = true;
            entry.terminal = true;
            entry.metadata = None;
            self.grants_reconciled = false;
        }
    }
}

/// Capacity is reserved before remote allocation, including every grant output.
/// Drop releases unused reservations on errors or cancellation; commit publishes
/// the entire validated bundle under the same lock used by ordinary registration.
/// Observed reservation replays pin existing incarnations instead of reserving
/// new slots. Retirement may proceed, but reclamation cannot steal those slots
/// before the authenticated replay completes (or its caller cancels).
pub(super) struct Admission {
    inner: Arc<Inner>,
    secrets: usize,
    grants: usize,
    secret_pins: BTreeMap<String, Arc<()>>,
    grant_pins: BTreeMap<String, Arc<()>>,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.lock() {
            self.release(&mut state);
        }
    }
}
impl Admission {
    fn release(&self, state: &mut State) {
        state.reserved_secrets -= self.secrets;
        state.reserved_grants -= self.grants;
        for (id, binding) in &self.secret_pins {
            if let Some(entry) = state.secrets.get_mut(id)
                && Arc::ptr_eq(binding, &entry.binding)
            {
                entry.admissions -= 1;
            }
        }
        for (id, binding) in &self.grant_pins {
            if let Some(entry) = state.grants.get_mut(id)
                && Arc::ptr_eq(binding, &entry.binding)
            {
                entry.admissions -= 1;
            }
        }
    }
    pub fn commit(
        self,
        secrets: Vec<(String, store::SecretOwner)>,
        grants: Vec<String>,
    ) -> Result<(), Status> {
        self.publish(secrets, grants, None)
    }
    pub fn commit_secret_reservation(
        self,
        intent: [u8; 32],
        response: &store::ReserveSecretResponse,
        owner: store::SecretOwner,
    ) -> Result<(), Status> {
        self.publish(
            vec![(response.reference.clone(), owner)],
            vec![],
            Some(Reservation::Secret(intent)),
        )
    }
    pub fn commit_grant_reservation(
        self,
        intent: [u8; 32],
        secrets: Vec<(String, store::SecretOwner)>,
        response: &refresh::ReserveGrantResponse,
    ) -> Result<(), Status> {
        self.publish(
            secrets,
            vec![response.grant.clone()],
            Some(Reservation::Grant(
                intent,
                response.output_references.clone(),
            )),
        )
    }
    fn publish(
        mut self,
        secrets: Vec<(String, store::SecretOwner)>,
        grants: Vec<String>,
        reservation: Option<Reservation>,
    ) -> Result<(), Status> {
        let inner = self.inner.clone();
        let mut state = inner.lock()?;
        let changed_outputs = match &reservation {
            Some(Reservation::Grant(_, outputs)) if !self.grant_pins.is_empty() => {
                self.grant_pins.keys().any(|id| {
                    state.grants[id].reservation.as_ref().is_none_or(|known| {
                        known.outputs.len() != outputs.len()
                            || known
                                .outputs
                                .iter()
                                .any(|(name, (reference, _))| outputs.get(name) != Some(reference))
                    })
                })
            }
            _ => false,
        };
        // An admitted replay may only reuse its authenticated allocation, not
        // register a different bundle using zero newly reserved capacity.
        let replay = !self.secret_pins.is_empty() || !self.grant_pins.is_empty();
        if changed_outputs
            || (replay
                && (secrets.len() != self.secret_pins.len()
                    || grants.len() != self.grant_pins.len()
                    || secrets
                        .iter()
                        .any(|(id, _)| !self.secret_pins.contains_key(id))
                    || grants.iter().any(|id| !self.grant_pins.contains_key(id))))
        {
            return Err(Status::failed_precondition(
                "issuer reservation binding changed",
            ));
        }
        self.release(&mut state);
        self.secrets = 0;
        self.grants = 0;
        self.secret_pins.clear();
        self.grant_pins.clear();
        let secret_id = secrets.first().map(|(id, _)| id.clone());
        let grant_id = grants.first().cloned();
        state.insert(secrets, grants)?;
        match reservation {
            Some(Reservation::Secret(intent)) => {
                state
                    .secrets
                    .get_mut(&secret_id.expect("reserved secret"))
                    .expect("inserted secret")
                    .reservation = Some(intent);
            }
            Some(Reservation::Grant(intent, outputs)) => {
                let outputs = outputs
                    .into_iter()
                    .map(|(name, id)| {
                        let binding = state.secrets[&id].binding.clone();
                        (name, (id, binding))
                    })
                    .collect();
                state
                    .grants
                    .get_mut(&grant_id.expect("reserved grant"))
                    .expect("inserted grant")
                    .reservation = Some(GrantReservation { intent, outputs });
            }
            None => {}
        }
        Ok(())
    }
}
impl Inner {
    pub fn admit(self: &Arc<Self>, secrets: usize, grants: usize) -> Result<Admission, Status> {
        let mut state = self.lock()?;
        state.capacity(secrets, grants)?;
        state.reserved_secrets += secrets;
        state.reserved_grants += grants;
        Ok(Admission {
            inner: self.clone(),
            secrets,
            grants,
            secret_pins: BTreeMap::new(),
            grant_pins: BTreeMap::new(),
        })
    }
    /// Only a successfully observed intent can reuse tracked capacity. Ordinary
    /// persisted registrations and unknown/lost responses still need admission.
    /// This is not a response cache: the issuer reauthorizes every replay RPC.
    pub fn admit_secret_reservation(
        self: &Arc<Self>,
        intent: [u8; 32],
    ) -> Result<Admission, Status> {
        let mut state = self.lock()?;
        if let Some((id, entry)) = state
            .secrets
            .iter_mut()
            .find(|(_, entry)| entry.reservation == Some(intent))
        {
            entry.admissions += 1;
            return Ok(Admission {
                inner: self.clone(),
                secrets: 0,
                grants: 0,
                secret_pins: BTreeMap::from([(id.clone(), entry.binding.clone())]),
                grant_pins: BTreeMap::new(),
            });
        }
        drop(state);
        self.admit(1, 0)
    }
    pub fn admit_grant_reservation(
        self: &Arc<Self>,
        intent: [u8; 32],
        owners: &HashMap<String, store::SecretOwner>,
    ) -> Result<Admission, Status> {
        let mut state = self.lock()?;
        let replay = state.grants.iter().find_map(|(id, entry)| {
            let reservation = entry.reservation.as_ref()?;
            if reservation.intent != intent
                || reservation.outputs.len() != owners.len()
                || !reservation.outputs.iter().all(|(name, (id, binding))| {
                    state.secrets.get(id).is_some_and(|secret| {
                        Arc::ptr_eq(binding, &secret.binding)
                            && owners
                                .get(name)
                                .is_some_and(|owner| same_owner(owner, &secret.owner))
                    })
                })
            {
                return None;
            }
            Some((
                id.clone(),
                entry.binding.clone(),
                reservation
                    .outputs
                    .values()
                    .cloned()
                    .collect::<BTreeMap<_, _>>(),
            ))
        });
        if let Some((id, binding, secret_pins)) = replay {
            for id in secret_pins.keys() {
                state
                    .secrets
                    .get_mut(id)
                    .expect("observed secret")
                    .admissions += 1;
            }
            state
                .grants
                .get_mut(&id)
                .expect("observed grant")
                .admissions += 1;
            return Ok(Admission {
                inner: self.clone(),
                secrets: 0,
                grants: 0,
                secret_pins,
                grant_pins: BTreeMap::from([(id, binding)]),
            });
        }
        drop(state);
        self.admit(owners.len(), 1)
    }
    pub fn track_secret(
        &self,
        bound_owner: store::SecretOwner,
        reference: String,
    ) -> Result<(), Status> {
        self.lock()?
            .insert(vec![(reference, owner(bound_owner)?)], vec![])
    }
    pub fn track_grant(&self, grant: String) -> Result<(), Status> {
        self.lock()?.insert(vec![], vec![grant])
    }
    pub fn observe_secrets(
        &self,
        request: &store::ResolveSecretsRequest,
    ) -> Result<Observation, Status> {
        let secrets = request
            .secrets
            .iter()
            .map(|input| {
                Ok((
                    input.reference.clone(),
                    owner(input.owner.clone().ok_or_else(|| {
                        Status::invalid_argument("invalid issuer reference binding")
                    })?)?,
                ))
            })
            .collect::<Result<Vec<_>, Status>>()?;
        let mut state = self.lock()?;
        state.insert(secrets, vec![])?;
        Ok(state.secret_observation(request.secrets.iter().map(|input| input.reference.clone())))
    }
    pub fn observe_grant(&self, grant: &str) -> Result<Observation, Status> {
        let mut state = self.lock()?;
        state.insert(vec![], vec![grant.to_owned()])?;
        Ok(state.grant_observation(std::iter::once(grant.to_owned())))
    }
    /// Local bookkeeping cannot turn a committed remote mutation into failure.
    /// On an unexpected bookkeeping error, discard all usable local snapshots;
    /// the mutation response still carries the durable binding to its caller.
    pub fn after_mutation(&self, result: Result<(), Status>) {
        if result.is_err_and(|error| error.code() != tonic::Code::Aborted) {
            let _ = self.unknown(super::ChangeKind::Secrets);
            let _ = self.unknown(super::ChangeKind::Grants);
            tracing::warn!("issuer mutation bookkeeping requires watch reconciliation");
        }
    }
}
