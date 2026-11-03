// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{Runtime, wire};
use crate::{ReferenceStateStore, auth::GatewayScope, repository::ScopedRepository};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

pub(super) async fn start(
    runtime: Arc<Runtime>,
    scope: GatewayScope,
    after: u64,
) -> Result<ReceiverStream<Result<wire::WatchSecretsResponse, Status>>, Status> {
    let mut shutdown = runtime.watch_shutdown.subscribe();
    if *shutdown.borrow() {
        return Err(Status::unavailable("issuer is shutting down"));
    }
    let permit = runtime
        .watches
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("issuer watch capacity exhausted"))?;
    let store = runtime.repository.for_gateway(&scope);
    let current = store.current_sequence().await?;
    let (sender, receiver) = mpsc::channel(64);
    tokio::spawn(async move {
        let _permit = permit;
        if *shutdown.borrow() {
            return;
        }
        tokio::select! {
            biased;
            _=shutdown.changed()=>{},
            ()=async {
                if let Err(error)=run(&runtime,&scope,store,after,current,&sender).await {let _=sender.send(Err(error)).await;}
            }=>{}
        }
    });
    Ok(ReceiverStream::new(receiver))
}
fn marker(sequence: u64, reset: bool) -> wire::WatchSecretsResponse {
    wire::WatchSecretsResponse {
        reference: String::new(),
        version: 0,
        sequence,
        reset_required: reset,
        revoked: false,
        checkpoint: !reset,
    }
}
async fn run(
    runtime: &Runtime,
    scope: &GatewayScope,
    store: ScopedRepository,
    after: u64,
    current: u64,
    sender: &mpsc::Sender<Result<wire::WatchSecretsResponse, Status>>,
) -> Result<(), Status> {
    let mut cursor = after;
    if after == 0 || after > current {
        cursor = current;
        if sender.send(Ok(marker(cursor, true))).await.is_err() {
            return Ok(());
        }
    }
    let refs = runtime.repository.references(scope);
    let mut heartbeat = tokio::time::Instant::now();
    let mut checkpoint = true;
    loop {
        let events = store.events_after(cursor, 128).await?;
        if !events.is_empty() {
            for event in events {
                cursor = event.sequence;
                if event.change.kind != "secret" {
                    continue;
                }
                match refs.load(&event.change.key).await {
                    Ok(Some(_)) => {}
                    Err(error) if error.code() == tonic::Code::PermissionDenied => continue,
                    Ok(None) => {
                        // Reference tombstones are retained. Missing metadata
                        // means the stream cannot prove a safe incremental view.
                        let _ = sender
                            .send(Ok(marker(store.current_sequence().await?, true)))
                            .await;
                        return Err(Status::data_loss("issuer watch metadata is unavailable"));
                    }
                    Err(error) => return Err(error),
                }
                let frame = wire::WatchSecretsResponse {
                    reference: event.change.key,
                    version: event.change.version,
                    sequence: event.sequence,
                    reset_required: false,
                    revoked: event.change.deleted,
                    checkpoint: false,
                };
                if sender.send(Ok(frame)).await.is_err() {
                    return Ok(());
                }
            }
            checkpoint = true;
            continue;
        }
        if checkpoint || heartbeat.elapsed() >= Duration::from_secs(5) {
            if sender.send(Ok(marker(cursor, false))).await.is_err() {
                return Ok(());
            }
            checkpoint = false;
            heartbeat = tokio::time::Instant::now();
        }
        tokio::select! { ()=sender.closed()=>return Ok(()), ()=tokio::time::sleep(Duration::from_millis(250))=>{} }
    }
}
