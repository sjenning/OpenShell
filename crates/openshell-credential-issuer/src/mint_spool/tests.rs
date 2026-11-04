// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{SecretOwner, auth::test_scope};

fn crypto(path: &std::path::Path) -> EncryptedGatewayCredentialStoreCrypto {
    EncryptedGatewayCredentialStoreCrypto::from_config(&toml::Table::from_iter([(
        "key_encryption_key_path".to_string(),
        toml::Value::String(path.to_str().unwrap().to_string()),
    )]))
    .unwrap()
}
fn grant() -> GrantIdentity {
    GrantIdentity {
        id: "grant".into(),
        authorization_epoch: "epoch".into(),
        owner: SecretOwner {
            workspace: "default".into(),
            provider_id: "provider".into(),
            credential_key: "TOKEN".into(),
            ..Default::default()
        },
    }
}
fn response() -> MintResponse {
    MintResponse {
        outputs: HashMap::from([("access_token".into(), "secret-access-token".into())]),
        expiration_time_ms: 1,
        rotated_secret_material: HashMap::from([(
            "refresh_token".into(),
            "secret-rotated-token".into(),
        )]),
    }
}

#[test]
fn known_results_survive_reopen_without_plaintext_even_when_outputs_expired() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("key");
    let spool = MintResultSpool::new(crypto(&key));
    let scope = test_scope("gateway");
    let bytes = spool
        .seal(&scope, &grant(), "attempt", &response())
        .unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for forbidden in [
        "secret-access-token",
        "secret-rotated-token",
        "access_token",
        "refresh_token",
    ] {
        assert!(!text.contains(forbidden));
    }
    assert!(!format!("{spool:?}").contains(key.to_str().unwrap()));
    let reopened = MintResultSpool::new(crypto(&key));
    let restored = reopened.open(&scope, &grant(), "attempt", &bytes).unwrap();
    assert_eq!(restored.outputs, response().outputs);
    assert_eq!(
        restored.rotated_secret_material,
        response().rotated_secret_material
    );
    assert_eq!(restored.expiration_time_ms, 1);
    assert_ne!(
        bytes,
        spool
            .seal(&scope, &grant(), "attempt", &response())
            .unwrap()
    );
}

#[test]
fn results_are_bound_to_gateway_owner_grant_epoch_and_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let spool = MintResultSpool::new(crypto(&directory.path().join("key")));
    let scope = test_scope("gateway");
    let bytes = spool
        .seal(&scope, &grant(), "attempt", &response())
        .unwrap();
    assert!(
        spool
            .open(&test_scope("other"), &grant(), "attempt", &bytes)
            .is_err()
    );
    assert!(spool.open(&scope, &grant(), "other", &bytes).is_err());
    let mut variants = [grant(), grant(), grant(), grant(), grant()];
    variants[0].id = "other".into();
    variants[1].authorization_epoch = "other".into();
    variants[2].owner.provider_id = "other".into();
    variants[3].owner.credential_key = "OTHER".into();
    variants[4].owner.workspace = "other".into();
    for variant in variants {
        assert!(spool.open(&scope, &variant, "attempt", &bytes).is_err());
    }
}

#[test]
fn oversized_results_are_rejected_before_envelope_allocation() {
    let directory = tempfile::tempdir().unwrap();
    let spool = MintResultSpool::new(crypto(&directory.path().join("key")));
    let mut result = response();
    result
        .outputs
        .insert("large".into(), "x".repeat(MAX_SOURCE + 1));
    assert_eq!(
        spool
            .seal(&test_scope("gateway"), &grant(), "attempt", &result)
            .unwrap_err()
            .code(),
        tonic::Code::ResourceExhausted
    );
}

#[test]
fn corruption_and_wrong_keys_fail_without_exposing_material() {
    let directory = tempfile::tempdir().unwrap();
    let spool = MintResultSpool::new(crypto(&directory.path().join("key")));
    let scope = test_scope("gateway");
    let bytes = spool
        .seal(&scope, &grant(), "attempt", &response())
        .unwrap();
    let wrong = MintResultSpool::new(crypto(&directory.path().join("other-key")));
    assert!(wrong.open(&scope, &grant(), "attempt", &bytes).is_err());
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    envelope["value"]["ciphertext"] = "AAAA".into();
    let error = spool
        .open(
            &scope,
            &grant(),
            "attempt",
            &serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap_err();
    assert!(!error.to_string().contains("secret-rotated-token"));
    assert!(
        spool
            .open(&scope, &grant(), "attempt", b"not-json")
            .is_err()
    );
    assert!(spool.seal(&scope, &grant(), "", &response()).is_err());
}
