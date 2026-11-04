// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared embedded/private issuer client. No mutation is automatically replayed.

use openshell_core::proto::credentials::{refresh::v1 as refresh, store::v1 as store};
use openshell_extension_core::{ExtensionChannelConfig, connect_channel};
use prost::Message;
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::{Request, Response, Status, transport::Channel};

mod transport;
mod validation;
mod watch;
mod watched;
pub use watch::RemoteWatch;
pub use watched::{ChangeKind, IssuerChange, WatchHealth, WatchedIssuer};
const LIMIT: usize = 1024 * 1024;
const ORDINARY: Duration = Duration::from_secs(10);
const REFRESH: Duration = Duration::from_mins(3);

#[derive(Clone)]
pub struct RemoteIssuer {
    store: transport::Store,
    refresh: transport::Refresh,
    calls: Arc<Semaphore>,
    watches: Arc<Semaphore>,
    capabilities: store::GetCapabilitiesResponse,
}
impl std::fmt::Debug for RemoteIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteIssuer").finish_non_exhaustive()
    }
}
fn failure(status: Status) -> Status {
    Status::new(status.code(), "remote issuer operation failed")
}
fn invalid() -> Status {
    Status::data_loss("remote issuer returned an invalid response")
}
impl RemoteIssuer {
    /// Requires explicit private trust and a reloadable client identity. Caller
    /// identity is negotiated by TLS; supplied owners are never authentication.
    pub async fn connect(config: &ExtensionChannelConfig) -> Result<Self, Status> {
        if !config.endpoint().starts_with("https://")
            || !config.has_custom_ca()
            || !config.has_client_identity()
        {
            return Err(Status::invalid_argument(
                "remote issuers require private-CA HTTPS and a client identity",
            ));
        }
        let channel = tokio::time::timeout(ORDINARY, connect_channel(config))
            .await
            .map_err(|_| Status::unavailable("remote issuer connection failed"))?
            .map_err(|_| Status::unavailable("remote issuer connection failed"))?;
        Self::discover(channel).await
    }
    async fn discover(channel: Channel) -> Result<Self, Status> {
        Self::discover_transports(
            transport::Store::remote(channel.clone()),
            transport::Refresh::remote(channel),
        )
        .await
    }
    /// Use the hosted handlers directly, with the fixed local identity and the
    /// same validation, admission limits, and watched-cache API as remote mode.
    /// Construct `store` with `CredentialStoreService::embedded` and construct
    /// `refresh` from that store. This never starts or connects to a listener.
    pub async fn embedded(
        store: crate::service::CredentialStoreService,
        refresh: crate::service::CredentialRefreshService,
    ) -> Result<Self, Status> {
        let this = Self::discover_transports(
            transport::Store::Embedded(store),
            transport::Refresh::Embedded(refresh),
        )
        .await?;
        // Verify both supplied services admit the local identity before handing
        // the client to watch controllers or gateway callers.
        this.list_strategies().await?;
        Ok(this)
    }
    async fn discover_transports(
        store: transport::Store,
        refresh: transport::Refresh,
    ) -> Result<Self, Status> {
        let mut this = Self {
            store,
            refresh,
            calls: Arc::new(Semaphore::new(16)),
            watches: Arc::new(Semaphore::new(2)),
            capabilities: store::GetCapabilitiesResponse::default(),
        };
        let mut client = this.store.clone();
        let capabilities = this
            .call(
                store::GetCapabilitiesRequest {},
                ORDINARY,
                move |request| async move { client.get_capabilities(request).await },
            )
            .await?;
        if capabilities.protocol_version != 1
            || !capabilities.supports_watch
            || !capabilities.supports_expiration
            || !capabilities.supports_metadata_inspection
            || capabilities.max_batch_size == 0
            || capabilities.max_batch_size > 64
            || capabilities.max_response_bytes == 0
            || capabilities.max_response_bytes > u32::try_from(LIMIT).expect("constant limit")
        {
            return Err(Status::failed_precondition(
                "remote issuer capabilities are incompatible",
            ));
        }
        this.capabilities = capabilities;
        Ok(this)
    }
    #[must_use]
    pub fn capabilities(&self) -> &store::GetCapabilitiesResponse {
        &self.capabilities
    }
    async fn permit(&self, slots: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Status> {
        tokio::time::timeout(ORDINARY, slots.clone().acquire_owned())
            .await
            .map_err(|_| Status::resource_exhausted("remote issuer admission timed out"))?
            .map_err(|_| Status::unavailable("remote issuer client closed"))
    }
    async fn call<Q, R, F, Fut>(&self, message: Q, deadline: Duration, call: F) -> Result<R, Status>
    where
        Q: Message,
        F: FnOnce(Request<Q>) -> Fut,
        Fut: Future<Output = Result<Response<R>, Status>>,
    {
        if message.encoded_len() > LIMIT {
            return Err(Status::resource_exhausted(
                "remote issuer request exceeds limit",
            ));
        }
        let _permit = self.permit(&self.calls).await?;
        let mut request = Request::new(message);
        request.set_timeout(deadline);
        tokio::time::timeout(deadline, call(request))
            .await
            .map_err(|_| Status::deadline_exceeded("remote issuer operation timed out"))?
            .map(Response::into_inner)
            .map_err(failure)
    }
    /// Allocate without values, so a gateway can durably journal ownership
    /// before sending a conditional fill. No automatic mutation replay.
    pub async fn reserve_secret(
        &self,
        message: store::ReserveSecretRequest,
    ) -> Result<store::ReserveSecretResponse, Status> {
        if !self.capabilities.supports_pending_reservations {
            return Err(Status::failed_precondition(
                "remote issuer does not support pending reservations",
            ));
        }
        let mut client = self.store.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.reserve_secret(request).await
            })
            .await?;
        if !validation::id(&result.reference) || result.version != 1 {
            return Err(invalid());
        }
        Ok(result)
    }
    pub async fn put_secret(
        &self,
        message: store::PutSecretRequest,
    ) -> Result<store::PutSecretResponse, Status> {
        let expected = message.reference.clone();
        let mut client = self.store.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.put_secret(request).await
            })
            .await?;
        if !validation::id(&result.reference)
            || result.version == 0
            || (!expected.is_empty() && expected != result.reference)
        {
            return Err(invalid());
        }
        Ok(result)
    }
    pub async fn delete_secret(
        &self,
        message: store::DeleteSecretRequest,
    ) -> Result<store::DeleteSecretResponse, Status> {
        let mut client = self.store.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.delete_secret(request).await
            })
            .await?;
        if result.version == 0 {
            return Err(invalid());
        }
        Ok(result)
    }
    pub async fn resolve_secrets(
        &self,
        message: store::ResolveSecretsRequest,
    ) -> Result<store::ResolveSecretsResponse, Status> {
        validation::requests(&message, self.capabilities.max_batch_size)?;
        let mut client = self.store.clone();
        let expected = message.clone();
        let started = std::time::Instant::now();
        let mut result = self
            .call(message, ORDINARY, move |request| async move {
                client.resolve_secrets(request).await
            })
            .await?;
        if result.encoded_len()
            > usize::try_from(self.capabilities.max_response_bytes).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        validation::resolved(&expected, &result)?;
        validation::bound_ttl(&mut result, started.elapsed())?;
        Ok(result)
    }
    pub async fn list_strategies(&self) -> Result<refresh::ListStrategiesResponse, Status> {
        let mut client = self.refresh.clone();
        let result = self
            .call(
                refresh::ListStrategiesRequest {},
                ORDINARY,
                move |request| async move { client.list_strategies(request).await },
            )
            .await?;
        validation::catalog(&result)?;
        Ok(result)
    }
    pub async fn create_grant(
        &self,
        message: refresh::CreateGrantRequest,
    ) -> Result<refresh::CreateGrantResponse, Status> {
        let outputs = message.outputs;
        let message = refresh::CreateGrantRequest {
            outputs: outputs.clone(),
            ..message
        };
        let mut client = self.refresh.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.create_grant(request).await
            })
            .await?;
        validation::created(&outputs, &result)?;
        Ok(result)
    }
    pub async fn reserve_grant(
        &self,
        message: refresh::ReserveGrantRequest,
    ) -> Result<refresh::ReserveGrantResponse, Status> {
        if !self.list_strategies().await?.supports_pending_reservations {
            return Err(Status::failed_precondition(
                "remote issuer does not support pending grant reservations",
            ));
        }
        let outputs = message.outputs.clone();
        let mut client = self.refresh.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.reserve_grant(request).await
            })
            .await?;
        validation::created(
            &outputs,
            &refresh::CreateGrantResponse {
                grant: result.grant.clone(),
                output_references: result.output_references.clone(),
            },
        )?;
        Ok(result)
    }
    pub async fn initialize_grant(
        &self,
        message: refresh::InitializeGrantRequest,
    ) -> Result<refresh::InitializeGrantResponse, Status> {
        let expected = message.grant.clone();
        let mut client = self.refresh.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.initialize_grant(request).await
            })
            .await?;
        validation::status(&expected, result.status.as_ref())?;
        if result
            .status
            .as_ref()
            .is_none_or(|status| status.state != "pending" || status.version != 2)
        {
            return Err(invalid());
        }
        Ok(result)
    }
    pub async fn get_grant(
        &self,
        message: refresh::GetGrantRequest,
    ) -> Result<refresh::GetGrantResponse, Status> {
        let expected = message.grant.clone();
        let mut client = self.refresh.clone();
        let result = self
            .call(message, ORDINARY, move |request| async move {
                client.get_grant(request).await
            })
            .await?;
        validation::status(&expected, result.status.as_ref())?;
        Ok(result)
    }
    pub async fn delete_grant(
        &self,
        message: refresh::DeleteGrantRequest,
    ) -> Result<refresh::DeleteGrantResponse, Status> {
        let mut client = self.refresh.clone();
        self.call(message, ORDINARY, move |request| async move {
            client.delete_grant(request).await
        })
        .await
    }
    pub async fn detach_grant(
        &self,
        message: refresh::DetachGrantRequest,
    ) -> Result<refresh::DetachGrantResponse, Status> {
        let mut client = self.refresh.clone();
        self.call(message, ORDINARY, move |request| async move {
            client.detach_grant(request).await
        })
        .await
    }
    pub async fn rotate_grant(
        &self,
        message: refresh::RotateGrantRequest,
    ) -> Result<refresh::RotateGrantResponse, Status> {
        let expected = message.grant.clone();
        let mut client = self.refresh.clone();
        let result = self
            .call(message, REFRESH, move |request| async move {
                client.rotate_grant(request).await
            })
            .await?;
        validation::status(&expected, result.status.as_ref())?;
        Ok(result)
    }
    pub async fn ensure_fresh(
        &self,
        message: refresh::EnsureFreshRequest,
    ) -> Result<refresh::EnsureFreshResponse, Status> {
        let expected = message.grant.clone();
        let mut client = self.refresh.clone();
        let result = self
            .call(message, REFRESH, move |request| async move {
                client.ensure_fresh(request).await
            })
            .await?;
        validation::status(&expected, result.status.as_ref())?;
        Ok(result)
    }
}
#[cfg(test)]
mod embedded_tests;
#[cfg(test)]
mod tests;
