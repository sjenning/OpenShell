// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn services(
    repository: Arc<Repository>,
    config: &toml::Table,
    policy: GatewayPolicy,
    minter: Arc<Minter>,
) -> (CredentialStoreService, CredentialRefreshService) {
    let driver: Arc<dyn CredentialDriver> = Arc::new(Driver {
        inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), config)
            .unwrap(),
        fail: minter.backend.clone(),
        resolves: Arc::default(),
        fail_resolves: Arc::default(),
    });
    let storage =
        CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
    let store =
        CredentialStoreService::new(repository, storage, policy, Duration::from_secs(2)).unwrap();
    let mut registry = MinterRegistry::default();
    registry.register_custom(minter).unwrap();
    let refresh = CredentialRefreshService::new(
        &store,
        Arc::new(registry),
        MintResultSpool::new(EncryptedGatewayCredentialStoreCrypto::from_config(config).unwrap()),
    )
    .unwrap();
    (store, refresh)
}
#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_refresh_replicas_coalesce_mints_recover_spools_and_replay_rotation_receipts() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("key").to_str().unwrap().into()),
    )]);
    let identity = format!(
        "spiffe://test.example/gateway/native-{}",
        uuid::Uuid::new_v4()
    );
    let scope = test_scope(&identity);
    let policy = GatewayPolicy::new(BTreeMap::from([(identity, vec!["default".into()])])).unwrap();
    let minter = Arc::new(Minter::default());
    let (store_a, a) = services(
        Repository::open(&url).await.unwrap(),
        &config,
        policy.clone(),
        minter.clone(),
    );
    let (_store_b, b) = services(
        Repository::open(&url).await.unwrap(),
        &config,
        policy,
        minter.clone(),
    );
    let (first, second) = tokio::join!(
        a.runtime
            .clone()
            .create(scope.clone(), request(), idempotency("create").unwrap()),
        b.runtime
            .clone()
            .create(scope.clone(), request(), idempotency("create").unwrap())
    );
    let grant = first.unwrap();
    assert_eq!(grant, second.unwrap());
    let (first, second) = tokio::join!(
        a.runtime.ensure(scope.clone(), grant.grant.clone(), 0),
        b.runtime.ensure(scope.clone(), grant.grant.clone(), 0)
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 1);
    minter.fail_backend.store(true, Ordering::SeqCst);
    assert!(
        a.runtime
            .rotate(
                scope.clone(),
                grant.grant.clone(),
                idempotency("rotate").unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        b.runtime
            .load(&scope, &grant.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Publishing
    );
    minter.backend.store(false, Ordering::SeqCst);
    b.runtime.tick().await.unwrap();
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
    let response = a
        .runtime
        .rotate(
            scope.clone(),
            grant.grant.clone(),
            idempotency("rotate").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status.unwrap().state, "refreshed");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
    let secrets = [("first", "TOKEN_ONE"), ("second", "TOKEN_TWO")]
        .into_iter()
        .map(|(name, key)| store_wire::ResolveSecretRequest {
            request_id: name.into(),
            owner: Some(store_wire::SecretOwner {
                credential_key: key.into(),
                ..owner()
            }),
            reference: grant.output_references[name].clone(),
            expected_version: Some(3),
        })
        .collect();
    let resolved = store_a
        .runtime
        .resolve(
            &scope,
            store_wire::ResolveSecretsRequest {
                secrets,
                purpose: store_wire::ResolvePurpose::OperatorExport as i32,
            },
        )
        .await
        .unwrap();
    assert_eq!(resolved.secrets[0].value, "first-2");
    b.runtime
        .clone()
        .delete(
            scope.clone(),
            grant.grant.clone(),
            idempotency("delete").unwrap(),
        )
        .await
        .unwrap();
    b.runtime.tick().await.unwrap();
    assert_eq!(
        a.runtime
            .load(&scope, &grant.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Deleted
    );
}
