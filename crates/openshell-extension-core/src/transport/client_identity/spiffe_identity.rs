// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SPIFFE is a local credential source, not an alternative TLS verifier.

use super::{IdentityMaterial, TransportError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spiffe::{SpiffeId, WorkloadApiClient, X509Svid};
use std::{path::Path, time::Duration};

pub(super) async fn load(
    endpoint: &str,
    expected: &str,
) -> Result<IdentityMaterial, TransportError> {
    let path = endpoint
        .strip_prefix("unix://")
        .ok_or(TransportError::ClientIdentity)?;
    if !Path::new(path).is_absolute() || path.is_empty() {
        return Err(TransportError::ClientIdentity);
    }
    let expected: SpiffeId = expected
        .parse()
        .map_err(|_| TransportError::ClientIdentity)?;
    tokio::time::timeout(Duration::from_secs(5), async {
        let client = WorkloadApiClient::connect_to(endpoint)
            .await
            .map_err(|_| TransportError::ClientIdentity)?;
        let svids = client
            .fetch_all_x509_svids()
            .await
            .map_err(|_| TransportError::ClientIdentity)?;
        select(svids, &expected)
    })
    .await
    .map_err(|_| TransportError::ClientIdentity)?
}

fn select(svids: Vec<X509Svid>, expected: &SpiffeId) -> Result<IdentityMaterial, TransportError> {
    let mut matches = svids
        .into_iter()
        .filter(|svid| svid.spiffe_id() == expected);
    let svid = matches.next().ok_or(TransportError::ClientIdentity)?;
    if matches.next().is_some() {
        return Err(TransportError::ClientIdentity);
    }
    let chain = svid
        .cert_chain()
        .iter()
        .map(|cert| CertificateDer::from(cert.as_bytes().to_vec()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        svid.private_key().as_bytes().to_vec(),
    ));
    Ok((chain, key))
}

#[cfg(all(test, unix))]
mod workload_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyUsagePurpose, SanType};

    pub(super) fn svid(id: &str) -> X509Svid {
        let key = openshell_crypto::pki::generate_keypair().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.subject_alt_names = vec![SanType::URI(id.try_into().unwrap())];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        let cert = openshell_crypto::pki::self_signed(params, &key).unwrap();
        X509Svid::parse_from_der(cert.der().as_ref(), &key.serialize_der().unwrap()).unwrap()
    }

    #[test]
    fn selects_exactly_the_configured_identity_not_the_default_or_first_svid() {
        let expected = "spiffe://test.example/gateway".parse().unwrap();
        let wanted = svid("spiffe://test.example/gateway");
        let other = svid("spiffe://other.example/gateway");
        let expected_bytes = wanted.leaf().as_bytes().to_vec();
        let (chain, _) = select(vec![other.clone(), wanted.clone()], &expected).unwrap();
        assert_eq!(chain[0].as_ref(), expected_bytes);
        assert!(select(vec![other], &expected).is_err());
        assert!(select(Vec::new(), &expected).is_err());
        assert!(select(vec![wanted.clone(), wanted], &expected).is_err());
    }

    #[tokio::test]
    async fn rejects_remote_workload_apis_invalid_ids_and_unavailable_sources() {
        for endpoint in [
            "http://127.0.0.1:1234",
            "https://workload.example",
            "unix://relative.sock",
            "unix://",
        ] {
            assert!(
                load(endpoint, "spiffe://test.example/gateway")
                    .await
                    .is_err()
            );
        }
        assert!(
            load("unix:///nonexistent/workload.sock", "not-an-id")
                .await
                .is_err()
        );
        assert!(
            load(
                "unix:///nonexistent/workload.sock",
                "spiffe://test.example/gateway"
            )
            .await
            .is_err()
        );
    }
}
