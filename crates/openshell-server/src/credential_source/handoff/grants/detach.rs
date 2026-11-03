// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Recoverable value-free conversion: claim gateway ownership, stop issuer
//! refresh, then atomically publish static handles and transfer journal ownership.
use super::super::{
    AtomicWrite, KIND, Phase, Provider, RemoteProviderSource, StaticHandoff, Store, encode,
    invalid, storage, wire,
};
use openshell_core::{GetResourceVersion as _, ObjectId as _};
use prost::Message as _;
use tonic::Status;

impl StaticHandoff {
    pub(crate) fn is_detaching(&self) -> bool {
        self.state
            .grant
            .as_ref()
            .is_some_and(|grant| grant.detaching)
    }
    /// Persist the claim before the issuer side effect. All normal retirement
    /// and metadata writes fence this journal revision and reject this claim.
    /// A disconnected caller leaves a recipe the reconciler can finish.
    pub(crate) async fn begin_detach(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
    ) -> Result<(), Status> {
        self.source(source)?;
        self.published_grant(provider)?;
        if self.is_detaching() {
            return Ok(());
        }
        if !source.client.list_strategies().await?.supports_grant_detach {
            return Err(Status::failed_precondition(
                "issuer does not support preserving refresh outputs",
            ));
        }
        let metadata = source
            .client
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: self
                    .state
                    .slots
                    .iter()
                    .map(|(key, slot)| {
                        Ok(wire::ResolveSecretRequest {
                            request_id: key.clone(),
                            owner: Some(self.owner(key)),
                            reference: slot.reference.clone().ok_or_else(invalid)?,
                            expected_version: None,
                        })
                    })
                    .collect::<Result<_, Status>>()?,
            })
            .await?;
        if metadata.secrets.iter().any(|secret| secret.pending_value) {
            return Err(Status::failed_precondition(
                "refresh outputs have no values to preserve; rotate before deleting refresh",
            ));
        }
        let mut claimed = self.state.clone();
        claimed.grant.as_mut().ok_or_else(invalid)?.detaching = true;
        store
            .write_atomically(&[
                AtomicWrite::Check {
                    object_type: "provider".into(),
                    id: provider.object_id().into(),
                    expected_version: provider.get_resource_version(),
                },
                AtomicWrite::Update {
                    object_type: KIND.into(),
                    id: self.state.id.clone(),
                    expected_version: self.revision,
                    payload: encode(&claimed)?,
                },
            ])
            .await
            .map_err(storage)?;
        self.state = claimed;
        self.revision = self.revision.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    pub(crate) async fn finish_detach(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<(), Status> {
        self.source(source)?;
        if self.state.phase != Phase::Published || !self.is_detaching() {
            return Err(invalid());
        }
        let provider = store
            .get_message::<Provider>(&self.state.provider_id)
            .await
            .map_err(storage)?
            .ok_or_else(invalid)?;
        let fence = match self.published_grant(&provider) {
            Ok(_) => self.check(store).await,
            Err(error) => Err(error),
        };
        if let Err(error) = fence {
            if self.observe_detached(store, source).await? {
                return Ok(());
            }
            return Err(error);
        }
        let grant = self.state.grant.as_ref().ok_or_else(invalid)?;
        source
            .client
            .detach_grant(
                openshell_core::proto::credentials::refresh::v1::DetachGrantRequest {
                    grant: grant.id.clone().ok_or_else(invalid)?,
                    idempotency_key: self.operation(&grant.plan.credential_key, "detach-grant")?,
                },
            )
            .await?;
        let mut candidate = provider.clone();
        for (key, slot) in &self.state.slots {
            candidate.credential_handles.insert(
                key.clone(),
                source.reference_handle(slot.reference.as_deref().ok_or_else(invalid)?, None)?,
            );
            // Expiry remains authoritative in the unchanged issuer reference.
            candidate.credential_expiration_times.remove(key);
        }
        let mut detached = self.state.clone();
        detached.grant = None;
        let result = store
            .write_atomically(&[
                AtomicWrite::Update {
                    object_type: "provider".into(),
                    id: provider.object_id().into(),
                    expected_version: provider.get_resource_version(),
                    payload: candidate.encode_to_vec(),
                },
                AtomicWrite::Update {
                    object_type: KIND.into(),
                    id: self.state.id.clone(),
                    expected_version: self.revision,
                    payload: encode(&detached)?,
                },
            ])
            .await
            .map(|_| ())
            .map_err(storage);
        if result.is_err() {
            // A reconciler or a lost commit response may have completed the
            // exact conversion. Do not repeat an effect against a replacement.
            if self.observe_detached(store, source).await? {
                return Ok(());
            }
            return result;
        }
        self.state = detached;
        self.revision = self.revision.checked_add(1).ok_or_else(invalid)?;
        Ok(())
    }
    async fn observe_detached(
        &mut self,
        store: &Store,
        source: &RemoteProviderSource,
    ) -> Result<bool, Status> {
        let Some(current) = Self::load(store, self.id()).await? else {
            return Ok(false);
        };
        let Some(provider) = store
            .get_message::<Provider>(&self.state.provider_id)
            .await
            .map_err(storage)?
        else {
            return Ok(false);
        };
        if current.state.phase != Phase::Published
            || current.state.grant.is_some()
            || current.state.source != self.state.source
            || current.state.workspace != self.state.workspace
            || current.state.provider_id != self.state.provider_id
            || !current.state.slots.keys().eq(self.state.slots.keys())
            || provider.metadata.as_ref().is_none_or(|meta| {
                meta.deletion_time.is_some()
                    || meta.workspace != self.state.workspace
                    || meta.id != self.state.provider_id
            })
        {
            return Ok(false);
        }
        for (key, slot) in &self.state.slots {
            if current.state.slots[key].reference != slot.reference
                || current.state.slots[key].retiring
                || provider.credential_handles.get(key)
                    != Some(
                        &source.reference_handle(
                            slot.reference.as_deref().ok_or_else(invalid)?,
                            None,
                        )?,
                    )
            {
                return Ok(false);
            }
        }
        *self = current;
        Ok(true)
    }
}
