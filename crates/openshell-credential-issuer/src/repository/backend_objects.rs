// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Physical encrypted-object adapter. Never use a gateway-selected namespace.

use super::{Mutation, Repository, ScopedRepository};
use async_trait::async_trait;
use openshell_driver_db_credstore::{
    CredentialObjectWrite, DbCredstoreObjectStore, DbCredstoreWriteCondition,
    StoredCredentialObject,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tonic::Status;

#[derive(Debug)]
struct BackendObjects(ScopedRepository);
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    name: String,
    labels: Option<String>,
    payload: Vec<u8>,
}

impl Repository {
    /// Objects contain encrypted driver envelopes, not plaintext secret values.
    /// This internal partition cannot be selected through a gateway scope.
    pub fn backend_objects(self: &Arc<Self>) -> Arc<dyn DbCredstoreObjectStore> {
        Arc::new(BackendObjects(ScopedRepository {
            repository: self.clone(),
            namespace: "_issuer-encrypted-backend-v1".to_string(),
            creator: "_issuer".to_string(),
        }))
    }
}
#[async_trait]
impl DbCredstoreObjectStore for BackendObjects {
    async fn get_credential_object(
        &self,
        object_type: &str,
        id: &str,
        _operation: &'static str,
    ) -> Result<Option<StoredCredentialObject>, Status> {
        let Some(record) = self.0.load(object_type, id).await? else {
            return Ok(None);
        };
        let envelope: Envelope = serde_json::from_slice(&record.payload)
            .map_err(|_| Status::data_loss("invalid issuer backend object"))?;
        if envelope.version != 1 {
            return Err(Status::failed_precondition(
                "unsupported issuer backend object version",
            ));
        }
        Ok(Some(StoredCredentialObject {
            object_type: object_type.to_string(),
            id: id.to_string(),
            payload: envelope.payload,
            resource_version: record.revision,
        }))
    }
    async fn put_credential_object(
        &self,
        write: CredentialObjectWrite,
        _operation: &'static str,
    ) -> Result<(), Status> {
        let payload = serde_json::to_vec(&Envelope {
            version: 1,
            name: write.name,
            labels: write.labels,
            payload: write.payload,
        })
        .map_err(|_| Status::internal("issuer backend object encoding failed"))?;
        let expected = match write.condition {
            DbCredstoreWriteCondition::MustCreate => None,
            DbCredstoreWriteCondition::MatchResourceVersion(revision) => Some(revision),
        };
        self.0
            .commit(
                &[Mutation::Put {
                    kind: write.object_type,
                    key: write.id,
                    expected,
                    payload,
                }],
                &[],
            )
            .await?;
        Ok(())
    }
    async fn delete_credential_object(
        &self,
        object_type: &str,
        id: &str,
        expected_resource_version: u64,
        _operation: &'static str,
    ) -> Result<(), Status> {
        self.0
            .commit(
                &[Mutation::Delete {
                    kind: object_type.to_string(),
                    key: id.to_string(),
                    expected: expected_resource_version,
                }],
                &[],
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
