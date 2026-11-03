// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_configured_daemons_share_versioned_values_and_exact_mutation_receipts() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL").unwrap();
    let mut first = Fixture::new().await;
    let mut second = Fixture::new().await;
    let key = first.directory.path().join("shared.key");
    let crypto = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(key.to_str().unwrap().into()),
    )]);
    EncryptedGatewayCredentialStoreCrypto::from_config(&crypto).unwrap();
    let start = |mut options: Config, listener: TcpListener| {
        let url = url.clone();
        let key = key.clone();
        async move {
            options.openshell.credential_issuer.database_url = url;
            options.openshell.credential_issuer.replicas = 2;
            options.openshell.credential_issuer.key_encryption_key_path = key;
            let daemon = Daemon::new(options).await.unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let task = tokio::spawn(async move {
                daemon
                    .serve_on(listener, async {
                        let _ = stopped.await;
                    })
                    .await
            });
            (stop, task)
        }
    };
    let (stop_a, task_a) = start(
        Config::parse(&first.config).unwrap(),
        first.listener.take().unwrap(),
    )
    .await;
    let (stop_b, task_b) = start(
        Config::parse(&second.config).unwrap(),
        second.listener.take().unwrap(),
    )
    .await;
    let a = RemoteIssuer::connect(&first.client).await.unwrap();
    let b = RemoteIssuer::connect(&second.client).await.unwrap();
    let unique = uuid::Uuid::new_v4().to_string();
    let owner = wire::SecretOwner {
        provider_id: unique.clone(),
        ..owner()
    };
    let reservation = wire::ReserveSecretRequest {
        owner: Some(owner.clone()),
        idempotency_key: format!("reserve-{unique}"),
    };
    let (one, two) = tokio::join!(
        a.reserve_secret(reservation.clone()),
        b.reserve_secret(reservation)
    );
    let reserved = one.unwrap();
    assert_eq!(two.unwrap(), reserved);
    let request = wire::PutSecretRequest {
        owner: Some(owner.clone()),
        reference: reserved.reference,
        expected_version: Some(1),
        value: "first-replica".into(),
        idempotency_key: format!("put-{unique}"),
        ..Default::default()
    };
    let original = a.put_secret(request.clone()).await.unwrap();
    assert_eq!(b.put_secret(request).await.unwrap(), original);
    let updated = b
        .put_secret(wire::PutSecretRequest {
            owner: Some(owner.clone()),
            reference: original.reference.clone(),
            expected_version: Some(2),
            value: "second-replica".into(),
            idempotency_key: format!("replace-{unique}"),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(updated.version, 3);
    let response = a
        .resolve_secrets(wire::ResolveSecretsRequest {
            purpose: wire::ResolvePurpose::SandboxDelivery as i32,
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "read".into(),
                owner: Some(owner),
                reference: original.reference,
                expected_version: Some(3),
            }],
        })
        .await
        .unwrap();
    assert_eq!(response.secrets[0].value, "second-replica");
    stop_a.send(()).unwrap();
    stop_b.send(()).unwrap();
    task_a.await.unwrap().unwrap();
    task_b.await.unwrap().unwrap();
}
