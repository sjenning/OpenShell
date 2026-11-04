// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::transport::WatchStream;
use super::{ORDINARY, RemoteIssuer, failure, invalid, refresh, store, validation};
use std::time::Duration;
use tokio::sync::OwnedSemaphorePermit;
use tonic::{Request, Status};

/// Bounded, value-free stream. A reset/checkpoint does not perform caller-side
/// reconciliation; consumers must keep their caches unavailable until it ends.
pub struct RemoteWatch<T> {
    stream: WatchStream<T>,
    _permit: OwnedSemaphorePermit,
    cursor: u64,
    terminated: bool,
}
impl<T> std::fmt::Debug for RemoteWatch<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteWatch")
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}
impl<T> RemoteWatch<T> {
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }
    fn check(
        &mut self,
        sequence: u64,
        reset: bool,
        checkpoint: bool,
        id: &str,
        version: u64,
        deleted: bool,
    ) -> Result<(), Status> {
        if reset {
            if checkpoint || !id.is_empty() || version != 0 || deleted {
                return Err(invalid());
            }
        } else if checkpoint {
            if sequence < self.cursor || !id.is_empty() || version != 0 || deleted {
                return Err(invalid());
            }
        } else if sequence <= self.cursor || !validation::id(id) || version == 0 {
            return Err(invalid());
        }
        self.cursor = sequence;
        Ok(())
    }
}
impl<T> RemoteWatch<T> {
    async fn read(&mut self) -> Result<Option<T>, Status> {
        if self.terminated {
            return Ok(None);
        }
        let result = tokio::time::timeout(Duration::from_secs(15), self.stream.message())
            .await
            .map_err(|_| Status::deadline_exceeded("remote issuer watch stalled"))
            .and_then(|result| result.map_err(failure));
        if !matches!(&result, Ok(Some(_))) {
            self.terminated = true;
        }
        result
    }
}
impl RemoteWatch<store::WatchSecretsResponse> {
    pub async fn message(&mut self) -> Result<Option<store::WatchSecretsResponse>, Status> {
        let message = self.read().await?;
        if let Some(value) = &message {
            self.check(
                value.sequence,
                value.reset_required,
                value.checkpoint,
                &value.reference,
                value.version,
                value.revoked,
            )
            .inspect_err(|_| self.terminated = true)?;
        }
        Ok(message)
    }
}
impl RemoteWatch<refresh::WatchGrantsResponse> {
    pub async fn message(&mut self) -> Result<Option<refresh::WatchGrantsResponse>, Status> {
        let message = self.read().await?;
        if let Some(value) = &message {
            self.check(
                value.sequence,
                value.reset_required,
                value.checkpoint,
                &value.grant,
                value.version,
                value.deleted,
            )
            .inspect_err(|_| self.terminated = true)?;
        }
        Ok(message)
    }
}
impl RemoteIssuer {
    pub async fn watch_secrets(
        &self,
        after_sequence: u64,
    ) -> Result<RemoteWatch<store::WatchSecretsResponse>, Status> {
        let permit = self.permit(&self.watches).await?;
        let mut client = self.store.clone();
        // Bound stream establishment, not the lifetime of an admitted watch.
        let stream = tokio::time::timeout(
            ORDINARY,
            client.watch_secrets(Request::new(store::WatchSecretsRequest { after_sequence })),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("remote issuer watch connection timed out"))?
        .map_err(failure)?
        .into_inner();
        Ok(RemoteWatch {
            stream,
            _permit: permit,
            cursor: after_sequence,
            terminated: false,
        })
    }
    pub async fn watch_grants(
        &self,
        after_sequence: u64,
    ) -> Result<RemoteWatch<refresh::WatchGrantsResponse>, Status> {
        let permit = self.permit(&self.watches).await?;
        let mut client = self.refresh.clone();
        let stream = tokio::time::timeout(
            ORDINARY,
            client.watch_grants(Request::new(refresh::WatchGrantsRequest { after_sequence })),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("remote issuer watch connection timed out"))?
        .map_err(failure)?
        .into_inner();
        Ok(RemoteWatch {
            stream,
            _permit: permit,
            cursor: after_sequence,
            terminated: false,
        })
    }
}

#[cfg(test)]
mod tests;
