// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Trusted, idempotent embedded upgrade. No migration operation is an RPC.
use super::{CredentialStoreService, VALUE_PURPOSE};
use crate::{
    ReferenceState, ReferenceStateStore as _, SecretOwner,
    repository::{Change, Mutation},
};
use openshell_core::proto::CredentialHandle;
use tonic::{Code, Status};
const IMPORT_KIND: &str = "embedded-reference-import-v1";
#[cfg(test)]
#[path = "migration_tests.rs"]
mod tests;
/// A legacy reference and its original physical backend authorization tuple.
/// Values never transit this metadata-only adoption path.
pub struct LegacyReference {
    pub reference: String,
    pub state: ReferenceState,
    pub registration: String,
    pub physical_provider: String,
    pub physical_owner_id: String,
    pub physical_key: String,
}
impl CredentialStoreService {
    /// Retain reference identity/version/tombstones and physical owner exactly.
    /// A durable import receipt fences a retry racing a legacy rotation. Once
    /// the issuer itself mutates a reference, adoption can never overwrite it.
    pub async fn import_legacy_reference(&self, legacy: LegacyReference) -> Result<(), Status> {
        let scope = self.embedded_scope()?;
        scope.authorize_owner(&legacy.state.owner)?;
        super::valid_reference(&legacy.reference)?;
        let refs = self.runtime.repository.references(&scope);
        let convert = |bytes: &[u8]| -> Result<Vec<u8>, Status> {
            use prost::Message as _;
            let handle = CredentialHandle::decode(bytes)
                .map_err(|_| Status::data_loss("invalid legacy credential handle"))?;
            self.runtime.storage.legacy_backing(
                &scope,
                &legacy.state.owner,
                crate::storage::LegacyPhysicalOwner {
                    registration: &legacy.registration,
                    provider: &legacy.physical_provider,
                    owner_id: &legacy.physical_owner_id,
                    credential_key: &legacy.physical_key,
                },
                VALUE_PURPOSE,
                &handle,
            )
        };
        let state = ReferenceState {
            backing: if legacy.state.backing.is_empty() {
                Vec::new()
            } else {
                convert(&legacy.state.backing)?
            },
            pending_deletions: legacy
                .state
                .pending_deletions
                .iter()
                .map(|value| convert(value))
                .collect::<Result<_, _>>()?,
            ..legacy.state
        };
        crate::authorize(&state, &state.owner)?;
        for _ in 0..8 {
            let current = refs.load(&legacy.reference).await?;
            let imported = refs.storage().load(IMPORT_KIND, &legacy.reference).await?;
            let expected = match (&current, &imported) {
                (None, None) => None,
                (Some(current), Some(imported)) => {
                    let previous: ReferenceState = super::decode(&imported.payload)?;
                    if current.state.owner != state.owner || previous.owner != state.owner {
                        return Err(Status::permission_denied("legacy reference owner changed"));
                    }
                    if previous == state {
                        return Ok(());
                    }
                    if current.state != previous
                        || state.version < current.state.version
                        || current.state.revoked
                    {
                        return Err(Status::aborted(
                            "legacy reference changed after issuer adoption",
                        ));
                    }
                    if state.version == previous.version
                        && (state.backing != previous.backing
                            || state.expiration_time_ms != previous.expiration_time_ms
                            || state.revoked != previous.revoked
                            || state.pending_value != previous.pending_value)
                    {
                        return Err(Status::data_loss(
                            "legacy reference changed without a new value version",
                        ));
                    }
                    Some(current.revision)
                }
                _ => {
                    return Err(Status::failed_precondition(
                        "legacy reference import ownership missing",
                    ));
                }
            };
            let payload = super::encode(&state)?;
            let mutations = [
                Mutation::Put {
                    kind: crate::repository::references::KIND.into(),
                    key: legacy.reference.clone(),
                    expected,
                    payload: payload.clone(),
                },
                Mutation::Put {
                    kind: IMPORT_KIND.into(),
                    key: legacy.reference.clone(),
                    expected: imported.as_ref().map(|record| record.revision),
                    payload,
                },
            ];
            let event = Change {
                kind: "secret".into(),
                key: legacy.reference.clone(),
                version: state.version,
                deleted: state.revoked,
            };
            match refs.storage().commit(&mutations, &[event]).await {
                Ok(_) => return Ok(()),
                Err(error) if matches!(error.code(), Code::AlreadyExists | Code::Aborted) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Status::aborted("legacy reference import conflicted"))
    }
    /// Import legacy internal owners through the same ownership/version rules.
    /// Physical driver registration remains issuer-owned after migration.
    pub fn legacy_storage_backing(
        &self,
        owner: &SecretOwner,
        registration: &str,
        physical_provider: &str,
        physical_key: &str,
        purpose: &str,
        handle: &CredentialHandle,
    ) -> Result<Vec<u8>, Status> {
        self.runtime.storage.legacy_backing(
            &self.embedded_scope()?,
            owner,
            crate::storage::LegacyPhysicalOwner {
                registration,
                provider: physical_provider,
                owner_id: &owner.provider_id,
                credential_key: physical_key,
            },
            purpose,
            handle,
        )
    }
}
