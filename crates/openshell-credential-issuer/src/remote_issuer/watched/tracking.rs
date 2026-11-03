// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Atomic admission and reclaimable terminal bindings. Active bindings are never evicted.
use super::{
    GRANTS, Grant, Inner, REFERENCES, Secret, State, WatchHealth, same_owner, store, validation,
};
use std::{collections::BTreeMap, sync::Arc};
use tonic::Status;

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
            self.secrets.retain(|_, entry| !entry.gone);
        }
        if self.grants.len() + self.reserved_grants + grants > GRANTS {
            self.grants.retain(|_, entry| !entry.gone);
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
                .retain(|id, entry| !entry.gone || owners.contains_key(id));
        }
        if self.grants.len() + self.reserved_grants + new_grants > GRANTS {
            self.grants
                .retain(|id, entry| !entry.gone || grants.contains(id));
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
            });
        }
        for grant in grants {
            self.grants.entry(grant).or_insert_with(|| Grant {
                metadata: None,
                version: 0,
                gone: false,
                terminal: false,
                binding: Arc::new(()),
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
pub(super) struct Admission {
    inner: Arc<Inner>,
    secrets: usize,
    grants: usize,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.lock() {
            state.reserved_secrets -= self.secrets;
            state.reserved_grants -= self.grants;
        }
    }
}
impl Admission {
    pub fn commit(
        mut self,
        secrets: Vec<(String, store::SecretOwner)>,
        grants: Vec<String>,
    ) -> Result<(), Status> {
        let mut state = self.inner.lock()?;
        state.reserved_secrets -= self.secrets;
        state.reserved_grants -= self.grants;
        self.secrets = 0;
        self.grants = 0;
        state.insert(secrets, grants)
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
        })
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
