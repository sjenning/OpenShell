// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Test-only watch lag; every authenticated unary call still uses the real issuer.
use super::*;
use openshell_core::proto::credentials::store::v1 as wire;
use tonic::{Request, Response};
use wire::credential_store_server::{CredentialStore, CredentialStoreServer};

pub(super) struct Store {
    pub inner: CredentialStoreService,
    pub hold: Arc<AtomicBool>,
}
impl Store {
    pub(super) fn into_service(self) -> CredentialStoreServer<Self> {
        CredentialStoreServer::new(self)
            .max_decoding_message_size(1024 * 1024)
            .max_encoding_message_size(1024 * 1024)
    }
}
#[tonic::async_trait]
impl CredentialStore for Store {
    async fn get_capabilities(
        &self,
        request: Request<wire::GetCapabilitiesRequest>,
    ) -> Result<Response<wire::GetCapabilitiesResponse>, Status> {
        self.inner.get_capabilities(request).await
    }
    async fn reserve_secret(
        &self,
        request: Request<wire::ReserveSecretRequest>,
    ) -> Result<Response<wire::ReserveSecretResponse>, Status> {
        self.inner.reserve_secret(request).await
    }
    async fn put_secret(
        &self,
        request: Request<wire::PutSecretRequest>,
    ) -> Result<Response<wire::PutSecretResponse>, Status> {
        self.inner.put_secret(request).await
    }
    async fn delete_secret(
        &self,
        request: Request<wire::DeleteSecretRequest>,
    ) -> Result<Response<wire::DeleteSecretResponse>, Status> {
        self.inner.delete_secret(request).await
    }
    async fn resolve_secrets(
        &self,
        request: Request<wire::ResolveSecretsRequest>,
    ) -> Result<Response<wire::ResolveSecretsResponse>, Status> {
        self.inner.resolve_secrets(request).await
    }
    type WatchSecretsStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<wire::WatchSecretsResponse, Status>> + Send>,
    >;
    async fn watch_secrets(
        &self,
        request: Request<wire::WatchSecretsRequest>,
    ) -> Result<Response<Self::WatchSecretsStream>, Status> {
        let stream = self.inner.watch_secrets(request).await?.into_inner();
        let hold = self.hold.clone();
        Ok(Response::new(Box::pin(stream.filter_map(move |event| {
            std::future::ready((!hold.load(Ordering::SeqCst)).then_some(event))
        }))))
    }
}
