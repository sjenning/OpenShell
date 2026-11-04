// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio_stream::StreamExt as _;

async fn next(
    stream: &mut tokio_stream::wrappers::ReceiverStream<Result<wire::WatchSecretsResponse, Status>>,
) -> wire::WatchSecretsResponse {
    tokio::time::timeout(Duration::from_secs(3), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
#[tokio::test]
async fn shutdown_releases_backpressured_watch_without_waiting_for_its_reader() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let mut stream = super::super::watch::start(runtime.clone(), test_scope(A), 0)
        .await
        .unwrap();
    let registry = runtime.repository.references(&test_scope(A)).registry();
    let owner = SecretOwner {
        workspace: "default".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    };
    for index in 0..80 {
        registry
            .reserve(&format!("reference-{index}"), &owner)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while tokio_stream::Stream::size_hint(&stream).0 < 64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.service.drain().await;
    let count = tokio::time::timeout(Duration::from_secs(1), async {
        let mut count = 0;
        while let Some(frame) = stream.next().await {
            frame.unwrap();
            count += 1;
        }
        count
    })
    .await
    .unwrap();
    assert_eq!(count, 64);
    assert_eq!(runtime.watches.available_permits(), 128);
}

#[tokio::test]
async fn reset_checkpoint_replay_and_identity_partitioning_are_durable() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let mut stream = super::super::watch::start(runtime.clone(), test_scope(A), 0)
        .await
        .unwrap();
    let reset = next(&mut stream).await;
    assert!(reset.reset_required);
    assert_eq!(reset.sequence, 0);
    let checkpoint = next(&mut stream).await;
    assert!(checkpoint.checkpoint);
    assert_eq!(checkpoint.sequence, 0);
    let first = create(&runtime).await;
    let event = next(&mut stream).await;
    assert_eq!(event.reference, first.reference);
    assert_eq!(event.version, 1);
    assert_eq!(event.sequence, 1);
    let checkpoint = next(&mut stream).await;
    assert!(checkpoint.checkpoint);
    assert_eq!(checkpoint.sequence, 1);
    let update = wire::PutSecretRequest {
        reference: first.reference.clone(),
        expected_version: Some(1),
        idempotency_key: "update".to_string(),
        ..put()
    };
    runtime
        .clone()
        .put(test_scope(A), update, idempotency("update").unwrap())
        .await
        .unwrap();
    drop(stream);
    let mut resumed = super::super::watch::start(runtime.clone(), test_scope(A), 1)
        .await
        .unwrap();
    let event = next(&mut resumed).await;
    assert_eq!(event.version, 2);
    assert_eq!(event.sequence, 2);
    assert_eq!(event.reference, first.reference);
    let mut other = super::super::watch::start(runtime.clone(), test_scope(B), 0)
        .await
        .unwrap();
    assert_eq!(next(&mut other).await.sequence, 0);
    assert!(next(&mut other).await.checkpoint);
    let mut unknown = super::super::watch::start(runtime, test_scope(A), u64::MAX)
        .await
        .unwrap();
    let reset = next(&mut unknown).await;
    assert!(reset.reset_required);
    assert_eq!(reset.sequence, 2);
}
