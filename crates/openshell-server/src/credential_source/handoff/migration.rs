// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Value-free ownership publication during trusted, pre-serving embedded upgrade.
use super::*;
impl StaticHandoff {
    /// Prepare the gateway half of an already-imported issuer bundle. The
    /// provider rewrite, legacy state removal and journal are one transaction.
    pub(crate) fn migration_write(
        source: &RemoteProviderSource,
        provider: &Provider,
        keys: &[String],
        grant: Option<(GrantPlan, String)>,
    ) -> Result<AtomicWrite, Status> {
        let identity = serde_json::to_vec(&(
            source.name.as_ref(),
            provider.object_workspace(),
            provider.object_id(),
            grant.as_ref().map(|(_, id)| id.as_str()),
            keys,
        ))
        .map_err(|_| invalid())?;
        let id = format!(
            "issuer-upgrade-{}",
            hex::encode(openshell_crypto::sha256(&identity).map_err(|_| invalid())?)
        );
        let slots = keys
            .iter()
            .map(|key| {
                let binding =
                    source.decode(provider.credential_handles.get(key).ok_or_else(invalid)?)?;
                Ok((
                    key.clone(),
                    Slot {
                        reference: Some(binding.reference),
                        filled: true,
                        retiring: false,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, Status>>()?;
        let state = State {
            format: 1,
            id: id.clone(),
            source: source.name.to_string(),
            workspace: provider.object_workspace().into(),
            provider_id: provider.object_id().into(),
            provider_name: provider.object_name().into(),
            expected_provider_version: None,
            phase: Phase::Published,
            slots,
            grant: grant.map(|(plan, id)| grants::GrantSlot {
                plan,
                id: Some(id),
                pending_publication: false,
                detaching: false,
            }),
        };
        if state.slots.is_empty() {
            return Err(invalid());
        }
        Ok(AtomicWrite::Create {
            object_type: KIND.into(),
            id: id.clone(),
            name: id,
            workspace: state.workspace.clone(),
            payload: encode(&state)?,
        })
    }

    /// A prepared import is not authority to run it. Recovery requires the
    /// provider and the atomically published ownership journal to agree on
    /// every output and the original immutable authorization epoch.
    pub(crate) async fn legacy_activation_published(
        store: &Store,
        source: &RemoteProviderSource,
        activation: &openshell_credential_issuer::service::LegacyGrantActivation,
    ) -> Result<bool, Status> {
        let identity = &activation.identity;
        let Some(provider) = store
            .get_message::<Provider>(&identity.owner.provider_id)
            .await
            .map_err(storage)?
        else {
            return Ok(false);
        };
        if provider.object_workspace() != identity.owner.workspace
            || identity.owner.kind != openshell_credential_issuer::SecretOwnerKind::Provider
        {
            return Err(invalid());
        }
        let keys = activation
            .outputs
            .values()
            .map(|output| output.credential_key.clone())
            .collect::<Vec<_>>();
        let bytes = serde_json::to_vec(&(
            source.name.as_ref(),
            provider.object_workspace(),
            provider.object_id(),
            Some(identity.id.as_str()),
            &keys,
        ))
        .map_err(|_| invalid())?;
        let id = format!(
            "issuer-upgrade-{}",
            hex::encode(openshell_crypto::sha256(&bytes).map_err(|_| invalid())?)
        );
        let Some(journal) = Self::load(store, &id).await? else {
            return Ok(false);
        };
        let published = journal.published_grant(&provider)?;
        let outputs = activation
            .outputs
            .iter()
            .map(|(name, output)| (name.clone(), output.credential_key.clone()))
            .collect::<BTreeMap<_, _>>();
        if published.source != source.name.as_ref()
            || published.grant != identity.id
            || published.credential_key != identity.owner.credential_key
            || journal.is_detaching()
            || journal.state.slots.len() != activation.outputs.len()
            || journal
                .state
                .grant
                .as_ref()
                .is_none_or(|grant| grant.plan.outputs != outputs)
        {
            return Err(invalid());
        }
        for output in activation.outputs.values() {
            let binding = source.decode(
                provider
                    .credential_handles
                    .get(&output.credential_key)
                    .ok_or_else(invalid)?,
            )?;
            if binding.reference != output.reference
                || binding.authorization_epoch.as_deref()
                    != Some(identity.authorization_epoch.as_str())
            {
                return Err(invalid());
            }
        }
        Ok(true)
    }
}
