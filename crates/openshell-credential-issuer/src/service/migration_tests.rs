// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{remote_issuer::RemoteIssuer, repository::Repository, storage::CredentialStorage};
use openshell_core::proto::credentials::{store::v1 as wire, v1::StoreCredentialRequest};
use openshell_driver_db_credstore::DbCredstoreCredentialDriver;
use prost::Message as _;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[tokio::test]
async fn reference_import_retries_synchronize_only_unmodified_native_state() {
    let directory = tempfile::tempdir().unwrap();
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let config = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("key").display().to_string()),
    )]);
    let driver = Arc::new(
        DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config).unwrap(),
    );
    let erased: Arc<dyn crate::backend::CredentialDriver> = driver.clone();
    let service = CredentialStoreService::embedded(
        repository,
        CredentialStorage::new(BTreeMap::from([("db".into(), erased)]), "db".into()).unwrap(),
        Duration::from_secs(1),
    )
    .unwrap();
    let owner = SecretOwner {
        workspace: "default".into(),
        provider_id: "provider-id".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    };
    let handle = driver
        .store_credential(StoreCredentialRequest {
            provider: "display".into(),
            workspace: "default".into(),
            provider_id: "provider-id".into(),
            credential_key: "TOKEN".into(),
            value: "legacy-private".into(),
            object_id: "allocation".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let state = ReferenceState {
        owner: owner.clone(),
        version: 1,
        backing: handle.encode_to_vec(),
        expiration_time_ms: None,
        revoked: false,
        pending_value: false,
        pending_deletions: Vec::new(),
    };
    let import = |state| LegacyReference {
        reference: "legacy-reference".into(),
        state,
        registration: "db".into(),
        physical_provider: "display".into(),
        physical_owner_id: "provider-id".into(),
        physical_key: "TOKEN".into(),
    };
    service
        .import_legacy_reference(import(state.clone()))
        .await
        .unwrap();
    service
        .import_legacy_reference(import(state.clone()))
        .await
        .unwrap();
    let mut rotated = state.clone();
    rotated.version = 2;
    rotated.expiration_time_ms = Some(4_000_000_000_000);
    service
        .import_legacy_reference(import(rotated.clone()))
        .await
        .unwrap();
    let observed = service
        .legacy_reference_state("legacy-reference", &owner)
        .await
        .unwrap();
    assert_eq!(observed.version, 2);
    assert_eq!(observed.expiration_time_ms, rotated.expiration_time_ms);
    let mut corrupt = rotated.clone();
    corrupt.expiration_time_ms = None;
    assert_eq!(
        service
            .import_legacy_reference(import(corrupt))
            .await
            .unwrap_err()
            .code(),
        Code::DataLoss
    );
    // A live issuer mutation takes over ownership. Replaying the exact original
    // import is harmless, but changed legacy state may never overwrite it.
    let refresh = crate::service::CredentialRefreshService::new(
        &service,
        Arc::new(crate::builtins::registry()),
        crate::mint_spool::MintResultSpool::new(
            openshell_driver_db_credstore::EncryptedGatewayCredentialStoreCrypto::from_config(
                &config,
            )
            .unwrap(),
        ),
    )
    .unwrap();
    let client = RemoteIssuer::embedded(service.clone(), refresh)
        .await
        .unwrap();
    client
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "default".into(),
                provider_id: "provider-id".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
            reference: "legacy-reference".into(),
            value: "native-private".into(),
            expected_version: Some(2),
            idempotency_key: "native-replacement".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    service
        .import_legacy_reference(import(rotated.clone()))
        .await
        .unwrap();
    rotated.version = 4;
    assert_eq!(
        service
            .import_legacy_reference(import(rotated))
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        service
            .legacy_reference_state("legacy-reference", &owner)
            .await
            .unwrap()
            .version,
        3
    );
    let mut foreign = state;
    foreign.owner.provider_id = "other-provider".into();
    assert_eq!(
        service
            .import_legacy_reference(import(foreign))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}
