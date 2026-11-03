// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reloadable outbound mTLS identities. TLS construction uses the crypto facade.

use super::{ExtensionChannelConfig, ExtensionServerTrust, TransportError, standard_endpoint};
use hyper_util::rt::TokioIo;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use std::{path::PathBuf, sync::Arc};
use tokio::net::TcpStream;
use tonic::transport::{Channel, Uri};
use tower::service_fn;

mod spiffe_identity;
type IdentityMaterial = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// Client certificate source, loaded again for every new TLS connection.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionClientIdentity {
    Pem {
        certificate: Vec<u8>,
        private_key: Vec<u8>,
    },
    /// Rotation must publish a matching certificate/key pair. Inconsistent,
    /// missing, or malformed replacements fail closed, never reuse old material.
    PemFiles {
        certificate: PathBuf,
        private_key: PathBuf,
    },
    /// Fetch this exact identity from a local SPIFFE Workload API on each dial.
    /// The endpoint must be an absolute unix:// socket, never a remote URL.
    Spiffe { endpoint: String, spiffe_id: String },
}

impl std::fmt::Debug for ExtensionClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pem { .. } => "Pem(<redacted>)",
            Self::PemFiles { .. } => "PemFiles(<redacted>)",
            Self::Spiffe { .. } => "Spiffe(<redacted>)",
        })
    }
}

impl ExtensionClientIdentity {
    async fn load(&self) -> Result<IdentityMaterial, TransportError> {
        match self {
            Self::Pem {
                certificate,
                private_key,
            } => parse_pem(certificate, private_key),
            Self::PemFiles {
                certificate,
                private_key,
            } => {
                // Detect replacement while reading, including projected-secret
                // symlink switches. A stable but mismatched pair fails TLS setup.
                for _ in 0..3 {
                    let cert = tokio::fs::read(certificate)
                        .await
                        .map_err(|_| TransportError::ClientIdentity)?;
                    let key = tokio::fs::read(private_key)
                        .await
                        .map_err(|_| TransportError::ClientIdentity)?;
                    let cert_again = tokio::fs::read(certificate)
                        .await
                        .map_err(|_| TransportError::ClientIdentity)?;
                    let key_again = tokio::fs::read(private_key)
                        .await
                        .map_err(|_| TransportError::ClientIdentity)?;
                    if cert == cert_again && key == key_again {
                        return parse_pem(&cert, &key);
                    }
                }
                Err(TransportError::ClientIdentity)
            }
            Self::Spiffe {
                endpoint,
                spiffe_id,
            } => spiffe_identity::load(endpoint, spiffe_id).await,
        }
    }
}

fn parse_pem(certificate: &[u8], private_key: &[u8]) -> Result<IdentityMaterial, TransportError> {
    let chain = CertificateDer::pem_slice_iter(certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TransportError::ClientIdentity)?;
    if chain.is_empty() {
        return Err(TransportError::ClientIdentity);
    }
    let key =
        PrivateKeyDer::from_pem_slice(private_key).map_err(|_| TransportError::ClientIdentity)?;
    Ok((chain, key))
}

async fn tls_config(
    config: &ExtensionChannelConfig,
) -> Result<rustls::ClientConfig, TransportError> {
    let mut roots = RootCertStore::empty();
    match config.server_trust() {
        ExtensionServerTrust::PlatformRoots => {
            for cert in rustls_native_certs::load_native_certs().certs {
                roots
                    .add(cert)
                    .map_err(|_| TransportError::ClientIdentity)?;
            }
        }
        ExtensionServerTrust::CustomCaPem(pem) => {
            for cert in CertificateDer::pem_slice_iter(pem) {
                roots
                    .add(cert.map_err(|_| TransportError::ClientIdentity)?)
                    .map_err(|_| TransportError::ClientIdentity)?;
            }
        }
    }
    if roots.is_empty() {
        return Err(TransportError::ClientIdentity);
    }
    let (chain, key) = config
        .client_identity
        .as_ref()
        .ok_or(TransportError::ClientIdentity)?
        .load()
        .await?;
    let mut tls = openshell_crypto::tls::try_client_builder()
        .map_err(|_| TransportError::ClientIdentity)?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| TransportError::ClientIdentity)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    Ok(tls)
}

pub(super) async fn connect(config: &ExtensionChannelConfig) -> Result<Channel, TransportError> {
    // Validate material before returning a channel as well as on every redial.
    // http only disables tonic's TLS layer; this connector always performs TLS.
    tls_config(config).await?;
    let config = config.clone();
    let uri = config.endpoint.replacen("https://", "http://", 1);
    standard_endpoint(&uri)?
        .connect_with_connector(service_fn(move |uri: Uri| {
            let config = config.clone();
            async move {
                let host = uri
                    .host()
                    .ok_or_else(|| std::io::Error::other("missing extension TLS hostname"))?
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string();
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| std::io::Error::other("invalid extension TLS hostname"))?;
                let tls = tls_config(&config).await.map_err(std::io::Error::other)?;
                let tcp =
                    TcpStream::connect((host.as_str(), uri.port_u16().unwrap_or(443))).await?;
                // This crate sits below openshell-core, so cannot use its wrapper.
                let _ = tcp.set_nodelay(true);
                let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                    .connect(name, tcp)
                    .await?;
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(std::io::Error::other(
                        "extension TLS did not negotiate HTTP/2",
                    ));
                }
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(TransportError::Connect)
}

#[cfg(test)]
mod tests;
