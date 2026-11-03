// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_core::proto::credentials::v1::ResolvedCredential;
use std::sync::Mutex;

#[derive(Debug)]
struct SlotDriver {
    inner: Arc<dyn CredentialDriver>,
    slots: Mutex<BTreeMap<String, CredentialHandle>>,
}
#[tonic::async_trait]
impl CredentialDriver for SlotDriver {
    async fn store_credential(
        &self,
        mut request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let provider = request.provider.clone();
        request.existing_handle = self.slots.lock().unwrap().get(&provider).cloned();
        let handle = self.inner.store_credential(request).await?;
        self.slots.lock().unwrap().insert(provider, handle.clone());
        Ok(handle)
    }
    async fn resolve_credentials(
        &self,
        request: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.inner.resolve_credentials(request).await
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }
}
#[tokio::test]
async fn fresh_physical_addresses_protect_even_legacy_owner_key_slot_drivers() {
    let (storage, _directory) = storage().await;
    let inner = storage.drivers["db"].clone();
    let driver: Arc<dyn CredentialDriver> = Arc::new(SlotDriver {
        inner,
        slots: Mutex::default(),
    });
    let storage =
        CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
    let scope = test_scope("gateway");
    let first = storage
        .stage(&scope, &owner(), "value-v1", "old".into())
        .await
        .unwrap();
    let second = storage
        .stage(&scope, &owner(), "value-v1", "new".into())
        .await
        .unwrap();
    assert_eq!(
        storage
            .resolve(&scope, &owner(), "value-v1", &first)
            .await
            .unwrap()
            .value,
        "old"
    );
    assert_eq!(
        storage
            .resolve(&scope, &owner(), "value-v1", &second)
            .await
            .unwrap()
            .value,
        "new"
    );
    let parsed: Backing = serde_json::from_slice(&second).unwrap();
    assert_eq!(parsed.version, 2);
    assert!(parsed.allocation.is_some());
    storage
        .delete(&scope, &owner(), "value-v1", &first)
        .await
        .unwrap();
    assert_eq!(
        storage
            .resolve(&scope, &owner(), "value-v1", &second)
            .await
            .unwrap()
            .value,
        "new"
    );
    let mut tampered: serde_json::Value = serde_json::from_slice(&second).unwrap();
    tampered["allocation"] = uuid::Uuid::new_v4().to_string().into();
    assert!(
        storage
            .resolve(
                &scope,
                &owner(),
                "value-v1",
                &serde_json::to_vec(&tampered).unwrap()
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn version_one_backings_remain_readable_and_deletable_without_readdressing() {
    let (storage, _directory) = storage().await;
    let scope = test_scope("gateway");
    let address = address(&scope, &owner(), "value-v1", None).unwrap();
    let handle = storage.drivers["db"]
        .store_credential(StoreCredentialRequest {
            provider: address.provider,
            credential_key: "VALUE".into(),
            value: "legacy-value".into(),
            existing_handle: None,
            workspace: address.workspace,
            provider_id: address.provider_id,
            object_id: uuid::Uuid::new_v4().to_string(),
        })
        .await
        .unwrap();
    let backing=serde_json::to_vec(&serde_json::json!({"version":1,"registration":"db","handle":handle.encode_to_vec(),"purpose":"value-v1"})).unwrap();
    assert_eq!(
        storage
            .resolve(&scope, &owner(), "value-v1", &backing)
            .await
            .unwrap()
            .value,
        "legacy-value"
    );
    storage
        .delete(&scope, &owner(), "value-v1", &backing)
        .await
        .unwrap();
    assert!(
        storage
            .resolve(&scope, &owner(), "value-v1", &backing)
            .await
            .is_err()
    );
}
