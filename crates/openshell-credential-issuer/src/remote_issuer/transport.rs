// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private adapters preserve one client validation/admission path. Embedded
//! calls invoke the generated service traits directly, never a loopback server.

use super::{LIMIT, refresh, store};
use crate::{
    auth::local_request,
    service::{CredentialRefreshService, CredentialStoreService},
};
use refresh::credential_refresh_server::CredentialRefresh as _;
use store::credential_store_server::CredentialStore as _;
use tokio_stream::{StreamExt as _, wrappers::ReceiverStream};
use tonic::{Request, Response, Status, Streaming, transport::Channel};

#[derive(Clone)]
pub(super) enum Store {
    Remote(Box<store::credential_store_client::CredentialStoreClient<Channel>>),
    Embedded(CredentialStoreService),
}
#[derive(Clone)]
pub(super) enum Refresh {
    Remote(Box<refresh::credential_refresh_client::CredentialRefreshClient<Channel>>),
    Embedded(CredentialRefreshService),
}

impl Store {
    pub(super) fn remote(channel: Channel) -> Self {
        Self::Remote(Box::new(
            store::credential_store_client::CredentialStoreClient::new(channel)
                .max_decoding_message_size(LIMIT)
                .max_encoding_message_size(LIMIT),
        ))
    }
}
impl Refresh {
    pub(super) fn remote(channel: Channel) -> Self {
        Self::Remote(Box::new(
            refresh::credential_refresh_client::CredentialRefreshClient::new(channel)
                .max_decoding_message_size(LIMIT)
                .max_encoding_message_size(LIMIT),
        ))
    }
}

// Concrete typed requests are essential here: no request metadata, identity
// parameter, or user-provided extension is accepted by the public client API.
macro_rules! unary {
    ($wire:ident; $($method:ident: $request:ident => $response:ident),+ $(,)?) => {
        $(pub(super) async fn $method(
            &mut self,
            request: Request<$wire::$request>,
        ) -> Result<Response<$wire::$response>, Status> {
            match self {
                Self::Remote(client) => client.$method(request).await,
                Self::Embedded(service) => service.$method(local_request(request)).await,
            }
        })+
    };
}
impl Store {
    unary!(store;
        get_capabilities: GetCapabilitiesRequest => GetCapabilitiesResponse,
        reserve_secret: ReserveSecretRequest => ReserveSecretResponse,
        put_secret: PutSecretRequest => PutSecretResponse,
        delete_secret: DeleteSecretRequest => DeleteSecretResponse,
        resolve_secrets: ResolveSecretsRequest => ResolveSecretsResponse,
    );
    pub(super) async fn watch_secrets(
        &mut self,
        request: Request<store::WatchSecretsRequest>,
    ) -> Result<Response<WatchStream<store::WatchSecretsResponse>>, Status> {
        match self {
            Self::Remote(client) => client
                .watch_secrets(request)
                .await
                .map(|response| response.map(|stream| WatchStream::Remote(Box::new(stream)))),
            Self::Embedded(service) => service
                .watch_secrets(local_request(request))
                .await
                .map(|response| response.map(WatchStream::Embedded)),
        }
    }
}
impl Refresh {
    unary!(refresh;
        list_strategies: ListStrategiesRequest => ListStrategiesResponse,
        create_grant: CreateGrantRequest => CreateGrantResponse,
        reserve_grant: ReserveGrantRequest => ReserveGrantResponse,
        initialize_grant: InitializeGrantRequest => InitializeGrantResponse,
        get_grant: GetGrantRequest => GetGrantResponse,
        delete_grant: DeleteGrantRequest => DeleteGrantResponse,
        detach_grant: DetachGrantRequest => DetachGrantResponse,
        rotate_grant: RotateGrantRequest => RotateGrantResponse,
        ensure_fresh: EnsureFreshRequest => EnsureFreshResponse,
    );
    pub(super) async fn watch_grants(
        &mut self,
        request: Request<refresh::WatchGrantsRequest>,
    ) -> Result<Response<WatchStream<refresh::WatchGrantsResponse>>, Status> {
        match self {
            Self::Remote(client) => client
                .watch_grants(request)
                .await
                .map(|response| response.map(|stream| WatchStream::Remote(Box::new(stream)))),
            Self::Embedded(service) => service
                .watch_grants(local_request(request))
                .await
                .map(|response| response.map(WatchStream::Embedded)),
        }
    }
}

pub(super) enum WatchStream<T> {
    Remote(Box<Streaming<T>>),
    Embedded(ReceiverStream<Result<T, Status>>),
}
impl<T> WatchStream<T> {
    pub(super) async fn message(&mut self) -> Result<Option<T>, Status> {
        match self {
            Self::Remote(stream) => stream.message().await,
            Self::Embedded(stream) => stream.next().await.transpose(),
        }
    }
}
