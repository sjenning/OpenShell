// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Retire replaced keys without reading or revoking untouched live credentials.
use super::{
    AtomicWrite, Phase, Provider, RemoteProviderSource, StaticHandoff, Store, invalid, retirement,
    storage, wire,
};
use openshell_core::{ObjectId as _, ObjectName as _, ObjectWorkspace as _};
use prost::Message as _;
use tonic::Status;
impl StaticHandoff {
    /// Update metadata or remove keys without reading any retained credential.
    /// Newly introduced or changed bindings require a value-bearing handoff.
    pub async fn update_preserving(
        store: &Store,
        source: &RemoteProviderSource,
        provider: &Provider,
        expected_version: u64,
        owned: &[Self],
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
        if provider.credential_handles.keys().any(|key| {
            old.credential_expiration_times.get(key)
                != provider.credential_expiration_times.get(key)
        }) {
            return Err(Status::failed_precondition(
                "retained issuer credential expiration requires a new credential value",
            ));
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
