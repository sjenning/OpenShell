// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_detach_serializes_with_other_replica_mint_and_preserves_latest_bundle() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let config = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("key").to_str().unwrap().into()),
    )]);
    let identity = format!(
        "spiffe://test.example/gateway/detach-{}",
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
    let created = a
        .runtime
        .clone()
        .create(scope.clone(), request(), idempotency("create").unwrap())
        .await
        .unwrap();
    a.runtime
        .ensure(scope.clone(), created.grant.clone(), 0)
        .await
        .unwrap();
    minter.block.store(true, Ordering::SeqCst);
    let grant = created.grant.clone();
    let runtime = a.runtime.clone();
    let rotation_scope = scope.clone();
    let rotation = tokio::spawn(async move {
        runtime
            .rotate(rotation_scope, grant, idempotency("rotate").unwrap())
            .await
    });
    minter.started.notified().await;
    let grant = created.grant.clone();
    let runtime = b.runtime.clone();
    let detach_scope = scope.clone();
    let detachment = tokio::spawn(async move {
        runtime
            .detach(detach_scope, grant, idempotency("detach").unwrap())
            .await
    });
    tokio::task::yield_now().await;
    assert!(!detachment.is_finished());
    minter.release.notify_one();
    rotation.await.unwrap().unwrap();
    detachment.await.unwrap().unwrap();
    assert_eq!(
        a.runtime
            .load(&scope, &created.grant)
            .await
            .unwrap()
            .state
            .phase,
        GrantPhase::Detached
    );
    a.runtime.tick().await.unwrap();
    b.runtime.tick().await.unwrap();
    let secrets = [("first", "TOKEN_ONE"), ("second", "TOKEN_TWO")]
        .into_iter()
        .map(|(name, key)| store_wire::ResolveSecretRequest {
            request_id: name.into(),
            owner: Some(store_wire::SecretOwner {
                credential_key: key.into(),
                ..owner()
            }),
            reference: created.output_references[name].clone(),
            expected_version: Some(3),
        })
        .collect();
    let values = store_a
        .runtime
        .resolve(
            &scope,
            store_wire::ResolveSecretsRequest {
                purpose: store_wire::ResolvePurpose::OperatorExport as i32,
                secrets,
            },
        )
        .await
        .unwrap();
    assert_eq!(values.secrets[0].value, "first-2");
    assert_eq!(values.secrets[1].value, "second-2");
    assert_eq!(minter.calls.load(Ordering::SeqCst), 2);
}
