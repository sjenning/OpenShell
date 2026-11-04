// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Code;

async fn stream() -> (
    mpsc::Sender<Result<store::WatchSecretsResponse, Status>>,
    RemoteWatch<store::WatchSecretsResponse>,
) {
    let (sender, receiver) = mpsc::channel(4);
    let permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
    (
        sender,
        RemoteWatch {
            stream: WatchStream::Embedded(ReceiverStream::new(receiver)),
            _permit: permit,
            cursor: 4,
            terminated: false,
        },
    )
}
fn event(sequence: u64) -> store::WatchSecretsResponse {
    store::WatchSecretsResponse {
        reference: "ref".into(),
        version: 1,
        sequence,
        ..Default::default()
    }
}

#[tokio::test]
async fn channel_watch_uses_identical_cursor_and_terminal_validation() {
    let (sender, mut watch) = stream().await;
    sender.send(Ok(event(5))).await.unwrap();
    assert_eq!(watch.message().await.unwrap().unwrap().sequence, 5);
    assert_eq!(watch.cursor(), 5);
    sender.send(Ok(event(5))).await.unwrap();
    assert_eq!(watch.message().await.unwrap_err().code(), Code::DataLoss);
    assert!(watch.message().await.unwrap().is_none());
}

#[tokio::test]
async fn channel_watch_validates_resets_checkpoints_and_sanitizes_errors() {
    let (sender, mut watch) = stream().await;
    sender
        .send(Ok(store::WatchSecretsResponse {
            sequence: 2,
            reset_required: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(watch.message().await.unwrap().unwrap().reset_required);
    assert_eq!(watch.cursor(), 2);
    sender
        .send(Ok(store::WatchSecretsResponse {
            sequence: 1,
            checkpoint: true,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(watch.message().await.unwrap_err().code(), Code::DataLoss);
    let (sender, mut watch) = stream().await;
    sender
        .send(Err(Status::with_details(
            Code::Unavailable,
            "private-diagnostic",
            b"private-details".to_vec().into(),
        )))
        .await
        .unwrap();
    let error = watch.message().await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "remote issuer operation failed");
    assert!(error.details().is_empty());
    assert!(watch.message().await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn channel_watch_stall_uses_the_same_deadline_and_cannot_resume() {
    let (_sender, mut watch) = stream().await;
    assert_eq!(
        watch.message().await.unwrap_err().code(),
        Code::DeadlineExceeded
    );
    assert!(watch.message().await.unwrap().is_none());
}
