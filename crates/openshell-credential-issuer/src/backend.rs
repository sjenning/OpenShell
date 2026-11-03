// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Storage driver contract shared by issuer provider storage and the gateway's
//! independent local internal-secret store. No provider or gateway database API.

use async_trait::async_trait;
use openshell_core::proto::{
    CredentialHandle,
    credentials::v1::{
        DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential,
        StoreCredentialRequest,
    },
};
use tonic::Status;

#[async_trait]
pub trait CredentialDriver: std::fmt::Debug + Send + Sync {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status>;
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status>;
    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status>;

    #[cfg(any(test, feature = "test-support"))]
    fn stored_credential_count(&self) -> Option<usize> {
        None
    }
    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_store(&self) {}
    #[cfg(any(test, feature = "test-support"))]
    fn fail_next_delete(&self) {}
    #[cfg(any(test, feature = "test-support"))]
    fn gate_next_resolve(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        None
    }
    #[cfg(any(test, feature = "test-support"))]
    fn gate_next_store(
        &self,
    ) -> Option<(
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        None
    }
}

macro_rules! storage_adapter {
    ($driver:ty) => {
        #[async_trait]
        impl CredentialDriver for $driver {
            async fn store_credential(
                &self,
                request: StoreCredentialRequest,
            ) -> Result<CredentialHandle, Status> {
                Self::store_credential(self, request).await
            }
            async fn delete_credential(
                &self,
                request: DeleteCredentialRequest,
            ) -> Result<(), Status> {
                Self::delete_credential(self, request).await
            }
            async fn resolve_credentials(
                &self,
                requests: Vec<ResolveCredentialRequest>,
            ) -> Result<Vec<ResolvedCredential>, Status> {
                Self::resolve_credentials(self, requests).await
            }
        }
    };
}
storage_adapter!(openshell_driver_db_credstore::DbCredstoreCredentialDriver);
storage_adapter!(openshell_driver_kubernetes_secrets::KubernetesSecretsCredentialDriver);
storage_adapter!(openshell_driver_vault::VaultCredentialDriver);
