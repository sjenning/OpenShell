// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod mtls;

use super::*;
use rcgen::{CertificateParams, SanType};

fn policy() -> GatewayPolicy {
    GatewayPolicy::new(BTreeMap::from([
        (
            "spiffe://test.example/gateway/a".to_string(),
            vec!["default".to_string()],
        ),
        (
            "spiffe://test.example/gateway/b".to_string(),
            vec!["default".to_string(), "other".to_string()],
        ),
    ]))
    .unwrap()
}
fn cert(uris: &[&str]) -> Vec<u8> {
    let key = openshell_crypto::pki::generate_keypair().unwrap();
    let mut params = CertificateParams::new(vec!["ignored-dns-name.test".to_string()]).unwrap();
    params.subject_alt_names.extend(
        uris.iter()
            .map(|uri| SanType::URI((*uri).try_into().unwrap())),
    );
    openshell_crypto::pki::self_signed(params, &key)
        .unwrap()
        .der()
        .to_vec()
}
fn owner() -> SecretOwner {
    SecretOwner {
        workspace: "default".to_string(),
        provider_id: "provider-id".to_string(),
        credential_key: "ACCESS_TOKEN".to_string(),
    }
}

#[test]
fn namespace_is_identity_bound_and_stable_across_certificate_rotations() {
    let policy = policy();
    let a = policy
        .scope_for_verified_certificate(&cert(&["spiffe://test.example/gateway/a"]))
        .unwrap();
    let rotated = policy
        .scope_for_verified_certificate(&cert(&["spiffe://test.example/gateway/a"]))
        .unwrap();
    let b = policy
        .scope_for_verified_certificate(&cert(&["spiffe://test.example/gateway/b"]))
        .unwrap();
    assert_eq!(a.namespace(), rotated.namespace());
    assert_ne!(a.namespace(), b.namespace());
    assert_eq!(a.namespace().len(), 64);
    assert_eq!(a.identity(), "spiffe://test.example/gateway/a");
    a.authorize_bound_owner(a.identity(), &owner(), &owner())
        .unwrap();
    assert_eq!(
        b.authorize_bound_owner(a.identity(), &owner(), &owner())
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
}

#[test]
fn bound_owners_are_immutable_and_workspace_scopes_are_not_wildcards() {
    let scope = policy()
        .scope_for_verified_certificate(&cert(&["spiffe://test.example/gateway/a"]))
        .unwrap();
    for field in 0..3 {
        let mut supplied = owner();
        match field {
            0 => supplied.workspace = "other".to_string(),
            1 => supplied.provider_id = "different-provider".to_string(),
            _ => supplied.credential_key = "OTHER_TOKEN".to_string(),
        }
        assert_eq!(
            scope
                .authorize_bound_owner(scope.identity(), &owner(), &supplied)
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
    assert!(scope.authorize_workspace("").is_err());
    assert!(scope.authorize_workspace("Default").is_err());
    let mut incomplete = owner();
    incomplete.provider_id.clear();
    assert_eq!(
        scope.authorize_owner(&incomplete).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

#[test]
fn rejects_missing_ambiguous_unconfigured_or_invalid_certificate_identities() {
    for uris in [
        vec![],
        vec![
            "spiffe://test.example/gateway/a",
            "spiffe://test.example/gateway/b",
        ],
        vec!["https://test.example/gateway/a"],
        vec!["spiffe://test.example/unconfigured"],
    ] {
        assert!(
            policy()
                .scope_for_verified_certificate(&cert(&uris))
                .is_err()
        );
    }
    assert!(
        policy()
            .scope_for_verified_certificate(b"not-a-certificate")
            .is_err()
    );
}

#[test]
fn headers_and_payload_owners_cannot_impersonate_tls_identity() {
    let mut request = Request::new(owner());
    request.metadata_mut().insert(
        "x-gateway-identity",
        "spiffe://test.example/gateway/a".parse().unwrap(),
    );
    request
        .metadata_mut()
        .insert("authorization", "Bearer forged".parse().unwrap());
    assert_eq!(
        policy().authenticate(&request).unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}

#[test]
fn configuration_must_explicitly_scope_every_gateway_identity() {
    assert!(GatewayPolicy::new(BTreeMap::new()).is_err());
    for (identity, workspaces) in [
        ("not-an-identity", vec!["default"]),
        ("spiffe://test.example/gateway", vec![]),
        ("spiffe://test.example/gateway", vec!["*"]),
        ("spiffe://test.example/gateway", vec![""]),
        ("spiffe://test.example/gateway", vec![" default"]),
        ("spiffe://test.example/gateway", vec!["default\n"]),
    ] {
        assert!(
            GatewayPolicy::new(BTreeMap::from([(
                identity.to_string(),
                workspaces.into_iter().map(str::to_string).collect()
            )]))
            .is_err()
        );
    }
}
