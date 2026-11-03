// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::StreamExt;
use openshell_extension_core::{
    ExtensionChannelConfig, ExtensionClientIdentity, ExtensionTlsAcceptor, connect_channel,
};
use rcgen::{BasicConstraints, ExtendedKeyUsagePurpose, IsCa};
use std::{
    convert::Infallible,
    future::{Ready, ready},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tonic::{body::Body, server::NamedService};
use tower::{Service, ServiceExt};

#[derive(Clone)]
struct Protected {
    policy: GatewayPolicy,
    reads: Arc<AtomicUsize>,
}
impl NamedService for Protected {
    const NAME: &'static str = "IssuerAuthTest";
}
impl Service<http::Request<Body>> for Protected {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let mut req = Request::new(());
        *req.extensions_mut() = request.extensions().clone();
        req.metadata_mut().insert(
            "x-gateway-identity",
            "spiffe://test.example/gateway/a".parse().unwrap(),
        );
        let authorized = self.policy.authenticate(&req).and_then(|scope| {
            scope.authorize_bound_owner("spiffe://test.example/gateway/a", &owner(), &owner())
        });
        let code = if authorized.is_ok() {
            self.reads.fetch_add(1, Ordering::SeqCst);
            200
        } else {
            403
        };
        ready(Ok(http::Response::builder()
            .status(code)
            .body(Body::empty())
            .unwrap()))
    }
}
fn client(
    ca: &openshell_crypto::pki::Certificate,
    ca_key: &openshell_crypto::pki::KeyPair,
    id: &str,
) -> ExtensionClientIdentity {
    let key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(id.try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert = openshell_crypto::pki::signed_by(params, &key, ca, ca_key).unwrap();
    ExtensionClientIdentity::Pem {
        certificate: cert.pem().into_bytes(),
        private_key: key.serialize_pem().unwrap().into_bytes(),
    }
}
async fn call(
    config: &ExtensionChannelConfig,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let mut channel = connect_channel(config).await?;
    channel.ready().await?;
    Ok(channel
        .call(
            http::Request::post(format!("{}/IssuerAuthTest/Resolve", config.endpoint()))
                .body(Body::empty())?,
        )
        .await?
        .status()
        .as_u16())
}

#[tokio::test]
async fn verified_connection_identity_cannot_be_overridden_by_matching_owner_or_headers() {
    openshell_crypto::tls::ensure_default_provider();
    let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = openshell_crypto::pki::self_signed(params, &ca_key).unwrap();
    let server_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = openshell_crypto::pki::signed_by(params, &server_key, &ca, &ca_key).unwrap();
    let acceptor = ExtensionTlsAcceptor::from_pem(
        cert.pem().as_bytes(),
        server_key.serialize_pem().unwrap().as_bytes(),
        ca.pem().as_bytes(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener)
        .map(move |socket| {
            let acceptor = acceptor.clone();
            async move {
                match socket {
                    Ok(socket) => acceptor.accept(socket).await.ok(),
                    Err(_) => None,
                }
            }
        })
        .buffer_unordered(16)
        .filter_map(|socket| async { socket.map(Ok::<_, std::io::Error>) });
    let reads = Arc::new(AtomicUsize::new(0));
    let service = Protected {
        policy: policy(),
        reads: reads.clone(),
    };
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(Box::pin(incoming))
            .await
            .unwrap();
    });
    let config = ExtensionChannelConfig::new(endpoint).with_custom_ca_pem(ca.pem());
    assert!(call(&config).await.is_err());
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        call(&config.clone().with_client_identity(client(
            &ca,
            &ca_key,
            "spiffe://test.example/gateway/a"
        )))
        .await
        .unwrap(),
        200
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        call(&config.clone().with_client_identity(client(
            &ca,
            &ca_key,
            "spiffe://test.example/gateway/b"
        )))
        .await
        .unwrap(),
        403
    );
    assert_eq!(
        call(&config.with_client_identity(client(
            &ca,
            &ca_key,
            "spiffe://test.example/unconfigured"
        )))
        .await
        .unwrap(),
        403
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    task.abort();
}
