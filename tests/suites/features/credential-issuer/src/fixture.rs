// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A real TokenMinter service plus a resource server, not an issuer substitute.
//! Only synthetic fixture tokens exist here. Every mint invalidates the previous
//! token, so a stale supervisor snapshot cannot make the resource probe pass.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    Router, extract::State, http::HeaderMap, http::StatusCode, routing::get,
    serve::ListenerExt as _,
};
use futures::StreamExt as _;
use openshell_core::proto::credentials::minter::v1::{self as wire, token_minter_server};
use openshell_credential_issuer::auth::IssuerPolicy;
use openshell_extension_core::ExtensionTlsAcceptor;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

const ISSUER_ID: &str = "spiffe://issuer-e2e.test/issuer/security";
const STRATEGY: &str = "custom:e2e";

#[derive(Clone)]
struct Minter {
    policy: IssuerPolicy,
    current: Arc<RwLock<Option<String>>>,
}

#[tonic::async_trait]
impl token_minter_server::TokenMinter for Minter {
    async fn describe(
        &self,
        request: Request<wire::DescribeRequest>,
    ) -> Result<Response<wire::DescribeResponse>, Status> {
        self.policy.authenticate(&request)?;
        Ok(Response::new(wire::DescribeResponse {
            strategies: vec![wire::StrategyDescriptor {
                name: STRATEGY.into(),
                config: vec![wire::MaterialDescriptor {
                    name: "audience".into(),
                    required: true,
                }],
                secret_material: vec![wire::MaterialDescriptor {
                    name: "seed".into(),
                    required: true,
                }],
                outputs: vec!["access_token".into()],
                rotated_secret_material: vec![],
            }],
        }))
    }

    async fn mint(
        &self,
        request: Request<wire::MintRequest>,
    ) -> Result<Response<wire::MintResponse>, Status> {
        self.policy.authenticate(&request)?;
        let request = request.into_inner();
        if request.strategy != STRATEGY
            || request.config != HashMap::from([("audience".into(), "resource".into())])
            || request.secret_material
                != HashMap::from([("seed".into(), "synthetic-e2e-seed".into())])
            || uuid::Uuid::parse_str(&request.attempt_id).is_err()
        {
            return Err(Status::invalid_argument(
                "invalid synthetic fixture mint request",
            ));
        }
        let token = format!("fixture-{}", request.attempt_id);
        *self.current.write().await = Some(token.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("clock before epoch"))?;
        Ok(Response::new(wire::MintResponse {
            outputs: HashMap::from([("access_token".into(), token)]),
            expiration_time: Some(prost_types::Timestamp {
                seconds: i64::try_from(now.as_secs()).expect("current Unix time fits i64") + 3600,
                nanos: 0,
            }),
            rotated_secret_material: HashMap::new(),
        }))
    }
}

async fn probe(
    State(current): State<Arc<RwLock<Option<String>>>>,
    headers: HeaderMap,
) -> StatusCode {
    let current = current.read().await;
    match current.as_ref() {
        Some(token)
            if headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                == Some(format!("Bearer {token}").as_str()) =>
        {
            StatusCode::NO_CONTENT
        }
        _ => StatusCode::UNAUTHORIZED,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls = ExtensionTlsAcceptor::from_pem(
        &std::fs::read("/fixture/tls.crt")?,
        &std::fs::read("/fixture/tls.key")?,
        &std::fs::read("/fixture/client-ca.pem")?,
    )?;
    let minter = Minter {
        policy: IssuerPolicy::new(vec![ISSUER_ID.into()])?,
        current: Arc::default(),
    };
    let http = Router::new()
        .route("/probe", get(probe))
        .route("/ready", get(|| async { StatusCode::NO_CONTENT }))
        .with_state(minter.current.clone());
    let http_listener = TcpListener::bind("0.0.0.0:8080")
        .await?
        .tap_io(|stream| openshell_core::net::set_tcp_nodelay_best_effort(stream));
    let listener = TcpListener::bind("0.0.0.0:8443").await?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .map(move |socket| {
            let tls = tls.clone();
            async move {
                let socket = socket?;
                let result =
                    tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await;
                Ok::<_, std::io::Error>(result.ok().and_then(Result::ok))
            }
        })
        .buffer_unordered(32)
        .filter_map(|result| async move {
            match result {
                Ok(Some(stream)) => Some(Ok(stream)),
                Ok(None) => None,
                Err(error) => Some(Err(error)),
            }
        });
    let grpc = tonic::transport::Server::builder()
        .add_service(token_minter_server::TokenMinterServer::new(minter))
        .serve_with_incoming(Box::pin(incoming));
    tokio::try_join!(async { grpc.await.map_err(std::io::Error::other) }, async {
        axum::serve(http_listener, http).await
    },)?;
    Ok(())
}
