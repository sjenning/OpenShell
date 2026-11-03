// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{auth::test_scope, repository::Repository};
use openshell_driver_db_credstore::DbCredstoreCredentialDriver;
mod allocations;

fn owner() -> SecretOwner {
    SecretOwner {
        workspace: "default".to_string(),
        provider_id: "provider-id".to_string(),
        credential_key: "TOKEN".to_string(),
    }
}
async fn storage() -> (CredentialStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let mut config = toml::Table::new();
    config.insert(
        "key_encryption_key_path".to_string(),
        toml::Value::String(dir.path().join("key.bin").display().to_string()),
    );
    let driver: Arc<dyn CredentialDriver> = Arc::new(
        DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config).unwrap(),
    );
    (
        CredentialStorage::new(
            BTreeMap::from([("db".to_string(), driver)]),
            "db".to_string(),
        )
        .unwrap(),
        dir,
    )
}
#[tokio::test]
async fn physical_backend_ownership_is_bound_to_gateway_owner_and_purpose() {
    let (storage, _dir) = storage().await;
    let a = test_scope("a");
    let b = test_scope("b");
    let backing = storage
        .stage(&a, &owner(), "value-v1", "private-secret".to_string())
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&backing).contains("private-secret"));
    let value = storage
        .resolve(&a, &owner(), "value-v1", &backing)
        .await
        .unwrap();
    assert_eq!(value.value, "private-secret");
    assert!(!format!("{value:?}").contains("private-secret"));
    assert!(
        storage
            .resolve(&b, &owner(), "value-v1", &backing)
            .await
            .is_err()
    );
    assert!(
        storage
            .delete(&b, &owner(), "value-v1", &backing)
            .await
            .is_err()
    );
    assert!(
        storage
            .resolve(&a, &owner(), "fingerprint-v1", &backing)
            .await
            .is_err()
    );
    let mut other = owner();
    other.provider_id = "different-provider".to_string();
    assert!(
        storage
            .resolve(&a, &other, "value-v1", &backing)
            .await
            .is_err()
    );
    other = owner();
    other.workspace = "unauthorized".to_string();
    assert_eq!(
        storage
            .stage(&a, &other, "value-v1", "must-not-store".to_string())
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        storage
            .resolve(&a, &owner(), "value-v1", &backing)
            .await
            .unwrap()
            .value,
        "private-secret"
    );
    storage
        .delete(&a, &owner(), "value-v1", &backing)
        .await
        .unwrap();
    assert!(
        storage
            .resolve(&a, &owner(), "value-v1", &backing)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn staging_never_overwrites_an_existing_candidate() {
    let (storage, _dir) = storage().await;
    let a = test_scope("a");
    let first = storage
        .stage(&a, &owner(), "value-v1", "old".to_string())
        .await
        .unwrap();
    let second = storage
        .stage(&a, &owner(), "value-v1", "new".to_string())
        .await
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(
        storage
            .resolve(&a, &owner(), "value-v1", &first)
            .await
            .unwrap()
            .value,
        "old"
    );
    assert_eq!(
        storage
            .resolve(&a, &owner(), "value-v1", &second)
            .await
            .unwrap()
            .value,
        "new"
    );
}
#[test]
fn addresses_are_unambiguous_stable_and_safe_for_legacy_paths_and_labels() {
    let scope = test_scope("a");
    let one = address(&scope, &owner(), "value-v1", None).unwrap();
    let two = address(&scope, &owner(), "value-v1", None).unwrap();
    assert_eq!(one.provider, two.provider);
    assert!(one.provider.len() <= 63);
    assert!(one.workspace.len() <= 63);
    assert!(
        one.provider
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || b"issuer-".contains(&byte))
    );
    let mut unusual = owner();
    unusual.provider_id = "../untrusted/path".to_string();
    let other = address(&scope, &unusual, "value-v1", None).unwrap();
    assert!(!other.provider.contains(".."));
    assert_ne!(one.provider, other.provider);
    assert!(CredentialStorage::new(BTreeMap::new(), "missing".to_string()).is_err());
}
#[test]
fn backend_diagnostics_are_never_reflected() {
    let failure = error(Status::with_details(
        Code::Unavailable,
        "secret-message",
        b"secret-details".to_vec().into(),
    ));
    assert!(!failure.message().contains("secret"));
    assert!(failure.details().is_empty());
}
