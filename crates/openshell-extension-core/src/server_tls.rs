// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Facade-owned mTLS listener primitives with unforgeable connection metadata.

use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tonic::transport::server::Connected;

/// Verified TLS peer certificate, created only after an authenticated handshake.
/// A service must still authorize its identity; trusting a CA is not authorization.
#[derive(Debug, Clone)]
pub struct ExtensionPeer {
    certificate: Vec<u8>,
}
impl ExtensionPeer {
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }
}

#[derive(Clone)]
pub struct ExtensionTlsAcceptor(tokio_rustls::TlsAcceptor);

#[derive(Debug, thiserror::Error)]
#[error("extension mTLS server configuration or handshake failed")]
pub struct ServerTlsError;

impl ExtensionTlsAcceptor {
    /// Require a verified client chain for every connection. No anonymous mode,
    /// platform trust fallback, or caller-selected cryptographic implementation.
    pub fn from_pem(
        certificate: &[u8],
        key: &[u8],
        client_ca: &[u8],
    ) -> Result<Self, ServerTlsError> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(client_ca) {
            roots
                .add(cert.map_err(|_| ServerTlsError)?)
                .map_err(|_| ServerTlsError)?;
        }
        if roots.is_empty() {
            return Err(ServerTlsError);
        }
        let verifier = openshell_crypto::tls::try_client_certificate_verifier(Arc::new(roots))
            .map_err(|_| ServerTlsError)?;
        let chain = CertificateDer::pem_slice_iter(certificate)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ServerTlsError)?;
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| ServerTlsError)?;
        let mut config = openshell_crypto::tls::try_server_builder()
            .map_err(|_| ServerTlsError)?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)
            .map_err(|_| ServerTlsError)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self(tokio_rustls::TlsAcceptor::from(Arc::new(config))))
    }
    pub async fn accept(&self, socket: TcpStream) -> Result<ExtensionTlsStream, ServerTlsError> {
        // This foundational crate cannot depend on openshell-core's wrapper.
        let _ = socket.set_nodelay(true);
        let stream = tokio::time::timeout(Duration::from_secs(5), self.0.accept(socket))
            .await
            .map_err(|_| ServerTlsError)?
            .map_err(|_| ServerTlsError)?;
        let connection = stream.get_ref().1;
        if connection.alpn_protocol() != Some(b"h2") {
            return Err(ServerTlsError);
        }
        let leaf = connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or(ServerTlsError)?;
        let peer = ExtensionPeer {
            certificate: leaf.as_ref().to_vec(),
        };
        Ok(ExtensionTlsStream { stream, peer })
    }
}

pub struct ExtensionTlsStream {
    stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer: ExtensionPeer,
}
impl Connected for ExtensionTlsStream {
    type ConnectInfo = ExtensionPeer;
    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer.clone()
    }
}
impl AsyncRead for ExtensionTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for ExtensionTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
