// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Retire replaced keys without reading or revoking untouched live credentials.
use super::{
    AtomicWrite, Phase, Provider, RemoteProviderSource, StaticHandoff, Store, invalid, retirement,
    storage, wire,
};
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _};
use prost::Message as _;
use std::collections::HashSet;
use tonic::Status;

/// Explicit retained-expiration intent must survive spec merge, including a
/// clear of an absent field or a set equal to the stored legacy timestamp.
/// These authenticated owner/reference/version observations carry no values.
pub struct ExpirationIntent {
    secrets: Vec<wire::ResolveSecretRequest>,
}
impl ExpirationIntent {
    pub(crate) async fn capture(
        source: &RemoteProviderSource,
        old: &Provider,
        update: &Provider,
        clear_keys: &[String],
    ) -> Result<Self, Status> {
        let keys = update
            .credential_expiration_times
            .keys()
            .chain(clear_keys)
            .filter(|key| {
                old.credential_handles.contains_key(*key) && !update.credentials.contains_key(*key)
            })
            .collect::<HashSet<_>>();
        let mut secrets = keys
            .into_iter()
            .map(|key| {
                Ok(wire::ResolveSecretRequest {
                    request_id: key.clone(),
                    owner: Some(super::super::owner(old, key)?),
                    reference: source.decode(&old.credential_handles[key])?.reference,
                    expected_version: None,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        if !secrets.is_empty() {
            let metadata = source
                .client
                .resolve_secrets(wire::ResolveSecretsRequest {
                    purpose: wire::ResolvePurpose::MetadataInspection as i32,
                    secrets: secrets.clone(),
                })
                .await?;
            for secret in metadata.secrets {
                let key = &secret.request_id;
                let binding = source.decode(&old.credential_handles[key])?;
                if (secret.version > 1 || binding.grant.is_some())
                    && update
                        .credential_expiration_times
                        .get(key)
                        .map(openshell_core::time::timestamp_to_millis)
                        .transpose()
                        .map_err(|_| invalid())?
                        != RemoteProviderSource::expiration(old, key, &secret)?
                {
                    return Err(Status::failed_precondition(format!(
                        "credential expiration for '{key}' is issuer-owned; replace a static credential value or rotate refresh to establish a new expiration"
                    )));
                }
                if secret.pending_value && binding.grant.is_none() {
                    return Err(Status::failed_precondition(
                        "pending issuer credential expiration requires a new credential value",
                    ));
                }
                secrets
                    .iter_mut()
                    .find(|request| request.request_id == *key)
                    .ok_or_else(invalid)?
                    .expected_version = Some(secret.version);
            }
        }
        Ok(Self { secrets })
    }
    pub(crate) async fn check(
        &self,
        source: &RemoteProviderSource,
        provider: &Provider,
    ) -> Result<(), Status> {
        if self.secrets.is_empty() {
            return Ok(());
        }
        for request in &self.secrets {
            let key = &request.request_id;
            if request.owner.as_ref() != Some(&super::super::owner(provider, key)?)
                || source
                    .decode(provider.credential_handles.get(key).ok_or_else(invalid)?)?
                    .reference
                    != request.reference
                || request.expected_version.is_none()
            {
                return Err(invalid());
            }
        }
        source
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: self.secrets.clone(),
            })
            .await?;
        Ok(())
    }
}
impl StaticHandoff {
    /// Provider-authored expiration remains editable only for retained static
    /// legacy version-one references. Authenticate metadata at the issuer, not
    /// a potentially lagging watch: a version advance during validation must
    /// not authorize an ineffective edit. This never resolves secret values.
    pub(crate) async fn check_retained_expirations<'a>(
        source: &RemoteProviderSource,
        old: &Provider,
        provider: &Provider,
        replaced: impl Iterator<Item = &'a String>,
    ) -> Result<(), Status> {
        let replaced = replaced.collect::<HashSet<_>>();
        let mut secrets = Vec::new();
        for (key, handle) in &provider.credential_handles {
            if replaced.contains(key)
                || old.credential_handles.get(key) != Some(handle)
                || old.credential_expiration_times.get(key)
                    == provider.credential_expiration_times.get(key)
            {
                continue;
            }
            let binding = source.decode(handle)?;
            if binding.grant.is_some() {
                return Err(Status::failed_precondition(
                    "retained issuer credential expiration requires a new credential value",
                ));
            }
            secrets.push(wire::ResolveSecretRequest {
                request_id: key.clone(),
                owner: Some(super::super::owner(provider, key)?),
                reference: binding.reference,
                expected_version: Some(1),
            });
        }
        if secrets.is_empty() {
            return Ok(());
        }
        let metadata = source
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets,
            })
            .await?;
        if metadata.secrets.iter().any(|secret| secret.pending_value) {
            return Err(Status::failed_precondition(
                "pending issuer credential expiration requires a new credential value",
            ));
        }
        // The issuer and provider stores do not share a transaction. A later
        // issuer version always supersedes these legacy fields; at version one
        // projection still takes the minimum of provider and issuer expiration.
        // Never write an issuer expiration or pin delivery back to version one.
        Ok(())
    }

    /// Update metadata or remove keys without reading any retained credential value.
    /// Newly introduced or changed bindings require a value-bearing handoff.
    pub async fn update_preserving(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        expected_version: u64,
        owned: &[Self],
    ) -> Result<(), Status> {
        Self::update_preserving_with_expiration_intent(
            store,
            source,
            provider,
            expected_version,
            owned,
            None,
        )
        .await
    }
    pub(crate) async fn update_preserving_with_expiration_intent(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        expected_version: u64,
        owned: &[Self],
        expiration_intent: Option<&ExpirationIntent>,
    ) -> Result<(), Status> {
        let row = store
            .get("provider", provider.object_id())
            .await
            .map_err(storage)?
            .ok_or_else(|| Status::not_found("handoff provider not found"))?;
        if row.resource_version != expected_version {
            return Err(Status::aborted("handoff provider changed"));
        }
        let old = Provider::decode(row.payload.as_slice()).map_err(|_| invalid())?;
        if !provider.credentials.is_empty()
            || old.object_id() != provider.object_id()
            || old.object_workspace() != provider.object_workspace()
            || old.object_name() != provider.object_name()
            || row.workspace != provider.object_workspace()
            || provider
                .credential_handles
                .iter()
                .any(|(key, handle)| old.credential_handles.get(key) != Some(handle))
        {
            return Err(invalid());
        }
        let mut writes = retirement::claims(source, &old, Some(provider), owned)?;
        writes.push(AtomicWrite::UpdateLabeled {
            object_type: "provider".into(),
            id: provider.object_id().into(),
            payload: provider.encode_to_vec(),
            expected_version,
            labels: provider
                .metadata
                .as_ref()
                .ok_or_else(invalid)?
                .labels
                .clone(),
        });
        Self::check_retained_expirations(source, &old, provider, std::iter::empty()).await?;
        if let Some(intent) = expiration_intent {
            intent.check(source, provider).await?;
        }
        store.write_atomically(&writes).await.map_err(storage)?;
        Ok(())
    }
    /// Clean only the keys durably retired by a committed provider mutation.
    /// Active sibling keys keep their original owner, reference and journal.
    pub async fn cleanup_retired(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Published {
            return Err(invalid());
        }
        let keys: Vec<_> = self
            .state
            .slots
            .iter()
            .filter(|(_, slot)| slot.retiring)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.check(store).await?;
            let reference = self.state.slots[&key]
                .reference
                .clone()
                .ok_or_else(invalid)?;
            source
                .client
                .delete_secret(wire::DeleteSecretRequest {
                    owner: Some(self.owner(&key)),
                    reference,
                    expected_version: None,
                    idempotency_key: self.operation(&key, "abort")?,
                })
                .await?;
            self.state.slots.remove(&key);
            self.save(store).await?;
        }
        Ok(())
    }
}
