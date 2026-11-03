// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{GrantRuntime, wire};
use crate::{auth::GatewayScope, repository::ScopedRepository};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

fn marker(sequence: u64, reset: bool) -> wire::WatchGrantsResponse {
    wire::WatchGrantsResponse {
        grant: String::new(),
        version: 0,
        sequence,
        reset_required: reset,
        deleted: false,
        checkpoint: !reset,
    }
}
impl GrantRuntime {
    pub(super) async fn watch_grants(
        self: Arc<Self>,
        scope: GatewayScope,
        after: u64,
    ) -> Result<ReceiverStream<Result<wire::WatchGrantsResponse, Status>>, Status> {
        let permit = self
            .store
            .watches
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("issuer watch capacity exhausted"))?;
        let store = self.store.repository.for_gateway(&scope);
        let current = store.current_sequence().await?;
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = run(&self, &scope, store, after, current, &sender).await {
                let _ = sender.send(Err(error)).await;
            }
        });
        Ok(ReceiverStream::new(receiver))
    }
}
async fn run(
    runtime: &GrantRuntime,
    scope: &GatewayScope,
    store: ScopedRepository,
    after: u64,
    current: u64,
    sender: &mpsc::Sender<Result<wire::WatchGrantsResponse, Status>>,
) -> Result<(), Status> {
    let mut cursor = after;
    if after == 0 || after > current {
        cursor = current;
        if sender.send(Ok(marker(cursor, true))).await.is_err() {
            return Ok(());
        }
    }
    let grants = runtime.store.repository.grants(scope);
    let mut heartbeat = tokio::time::Instant::now();
    let mut checkpoint = true;
    loop {
        let events = store.events_after(cursor, 128).await?;
        if !events.is_empty() {
            for event in events {
                cursor = event.sequence;
                if event.change.kind != "grant" {
                    continue;
                }
                match grants.load(&event.change.key).await {
                    Ok(Some(_)) => {}
                    Err(error) if error.code() == tonic::Code::PermissionDenied => continue,
                    Ok(None) => {
                        let _ = sender
                            .send(Ok(marker(store.current_sequence().await?, true)))
                            .await;
                        return Err(Status::data_loss(
                            "issuer grant watch metadata is unavailable",
                        ));
                    }
                    Err(error) => return Err(error),
                }
                let frame = wire::WatchGrantsResponse {
                    grant: event.change.key,
                    version: event.change.version,
                    sequence: event.sequence,
                    reset_required: false,
                    deleted: event.change.deleted,
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
        tokio::select! {()=sender.closed()=>return Ok(()),()=tokio::time::sleep(Duration::from_millis(250))=>{}}
    }
}
