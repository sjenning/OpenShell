// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_extension_core::ExtensionClientIdentity;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[tokio::test]
async fn production_constructor_discovers_and_mints_over_mutually_authenticated_tls() {
    openshell_crypto::tls::ensure_default_provider();
    let ca_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = openshell_crypto::pki::self_signed(params, &ca_key).unwrap();
    let server_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = openshell_crypto::pki::signed_by(params, &server_key, &ca, &ca_key).unwrap();
    let client_key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["issuer.internal".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = openshell_crypto::pki::signed_by(params, &client_key, &ca, &ca_key).unwrap();
    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(
            server.pem(),
            server_key.serialize_pem().unwrap(),
        ))
        .client_ca_root(Certificate::from_pem(ca.pem()));
    let received = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let fake = Fake {
        descriptor: descriptor(),
        response: Ok(response()),
        received: received.clone(),
    };
    let task = tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(wire::token_minter_server::TokenMinterServer::new(fake))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let config = ExtensionChannelConfig::new(&endpoint)
        .with_custom_ca_pem(ca.pem())
        .with_client_identity(ExtensionClientIdentity::Pem {
            certificate: client.pem().into_bytes(),
            private_key: client_key.serialize_pem().unwrap().into_bytes(),
        });
    let minter = RemoteMinter::connect(&config, "test").await.unwrap();
    let mut registry = MinterRegistry::default();
    registry.register_custom(Arc::new(minter)).unwrap();
    let result = registry.mint(request()).await.unwrap();
    assert_eq!(result.outputs["access_token"], "minted-secret");
    assert_eq!(received.lock().unwrap().len(), 1);
    // The same TLS path must not accept an endpoint whose certificate does not
    // match its configured hostname, even with the correct CA and client key.
    let wrong_host = ExtensionChannelConfig::new(endpoint.replace("localhost", "127.0.0.1"))
        .with_custom_ca_pem(ca.pem())
        .with_client_identity(ExtensionClientIdentity::Pem {
            certificate: client.pem().into_bytes(),
            private_key: client_key.serialize_pem().unwrap().into_bytes(),
        });
    assert!(RemoteMinter::connect(&wrong_host, "test").await.is_err());
    task.abort();
}
