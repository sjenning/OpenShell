// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_crypto::{pki, tls};
use rustls::RootCertStore;
use std::sync::Arc;

#[test]
fn client_certificate_verifier_requires_explicit_trust_and_never_allows_anonymous_peers() {
    assert!(tls::try_client_certificate_verifier(Arc::new(RootCertStore::empty())).is_err());
    let key = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = pki::self_signed(params, &key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let verifier = tls::try_client_certificate_verifier(Arc::new(roots)).unwrap();
    assert!(verifier.offer_client_auth());
    assert!(verifier.client_auth_mandatory());
    let client_key = pki::generate_keypair().unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client = pki::signed_by(params, &client_key, &ca, &key).unwrap();
    verifier
        .verify_client_cert(client.der(), &[], rustls::pki_types::UnixTime::now())
        .unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let wrong_role = pki::signed_by(params, &client_key, &ca, &key).unwrap();
    assert!(
        verifier
            .verify_client_cert(wrong_role.der(), &[], rustls::pki_types::UnixTime::now())
            .is_err()
    );
    let rogue = pki::self_signed(rcgen::CertificateParams::default(), &client_key).unwrap();
    assert!(
        verifier
            .verify_client_cert(rogue.der(), &[], rustls::pki_types::UnixTime::now())
            .is_err()
    );
}
