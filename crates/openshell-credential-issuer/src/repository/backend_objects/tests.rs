// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::credentials::v1::{
    DeleteCredentialRequest, ResolveCredentialRequest, StoreCredentialRequest,
};
use openshell_driver_db_credstore::DbCredstoreCredentialDriver;

#[tokio::test]
async fn issuer_database_backend_encrypts_resolves_fences_and_deletes_without_gateway_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = toml::Table::new();
    config.insert(
        "key_encryption_key_path".to_string(),
        toml::Value::String(dir.path().join("key.bin").display().to_string()),
    );
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let objects = repository.backend_objects();
    let driver = DbCredstoreCredentialDriver::from_config(objects.clone(), &config).unwrap();
    let handle = driver
        .store_credential(StoreCredentialRequest {
            provider: "display-name".to_string(),
            credential_key: "TOKEN".to_string(),
            value: "private-value".to_string(),
            workspace: "default".to_string(),
            provider_id: "provider-id".to_string(),
            object_id: "staged-write-id".to_string(),
            existing_handle: None,
        })
        .await
        .unwrap();
    let id = openshell_driver_db_credstore::EncryptedGatewayCredentialStoreCrypto::id_from_handle(
        &handle,
    )
    .unwrap();
    let encrypted = objects
        .get_credential_object(openshell_driver_db_credstore::OBJECT_TYPE, &id, "test")
        .await
        .unwrap()
        .unwrap();
    assert!(!String::from_utf8_lossy(&encrypted.payload).contains("private-value"));
    let req = ResolveCredentialRequest {
        request_id: "attempt-local".to_string(),
        provider: "display-name".to_string(),
        credential_key: "TOKEN".to_string(),
        handle: Some(handle.clone()),
        workspace: "default".to_string(),
        provider_id: "provider-id".to_string(),
    };
    assert_eq!(
        driver.resolve_credentials(vec![req.clone()]).await.unwrap()[0].value,
        "private-value"
    );
    let wrong = ResolveCredentialRequest {
        provider: "other-provider".to_string(),
        ..req.clone()
    };
    assert!(driver.resolve_credentials(vec![wrong]).await.is_err());
    let err = objects
        .put_credential_object(
            CredentialObjectWrite {
                object_type: encrypted.object_type.clone(),
                id: id.clone(),
                name: "ignored-name".to_string(),
                payload: vec![],
                labels: None,
                condition: DbCredstoreWriteCondition::MatchResourceVersion(999),
            },
            "secret-operation",
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Aborted);
    assert!(!err.message().contains("secret-operation"));
    // The physical partition is not any authenticated gateway's metadata space.
    let scope = crate::auth::test_scope("a");
    assert!(
        repository
            .for_gateway(&scope)
            .load(openshell_driver_db_credstore::OBJECT_TYPE, &id)
            .await
            .unwrap()
            .is_none()
    );
    driver
        .delete_credential(DeleteCredentialRequest {
            provider: "display-name".to_string(),
            credential_key: "TOKEN".to_string(),
            handle: Some(handle),
            workspace: "default".to_string(),
            provider_id: "provider-id".to_string(),
        })
        .await
        .unwrap();
    assert!(
        objects
            .get_credential_object(openshell_driver_db_credstore::OBJECT_TYPE, &id, "test")
            .await
            .unwrap()
            .is_none()
    );
}
