// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{CANDIDATE_KIND, Candidate, Runtime, VALUE_PURPOSE, decode};
use crate::{ReferenceState, repository::Mutation};
use std::{sync::Arc, time::Duration};
use tonic::Status;

pub(super) fn spawn(
    runtime: &Arc<Runtime>,
    interval: Duration,
) -> Result<tokio::task::JoinHandle<()>, Status> {
    if interval.is_zero() {
        return Err(Status::invalid_argument(
            "issuer maintenance interval must be positive",
        ));
    }
    let runtime = Arc::downgrade(runtime);
    Ok(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Some(runtime) = runtime.upgrade() else {
                break;
            };
            if let Err(error) = runtime.maintenance().await {
                tracing::warn!(code=?error.code(), "issuer secret cleanup deferred");
            }
        }
    }))
}
impl Runtime {
    pub(super) async fn maintenance(&self) -> Result<(), Status> {
        for scope in self.policy.configured_scopes()? {
            let store = self.repository.for_gateway(&scope);
            let mut after = None;
            loop {
                let page = store.list(CANDIDATE_KIND, after.as_deref(), 128).await?;
                if page.is_empty() {
                    break;
                }
                for (key, record) in page {
                    after = Some(key.clone());
                    let candidate: Candidate = decode(&record.payload)?;
                    if scope.authorize_owner(&candidate.owner).is_err() {
                        continue;
                    }
                    let coordination = format!("{}:{}", scope.namespace(), candidate.operation_key);
                    let lock = self.coordinator.lock_for(&coordination)?;
                    let Ok(_guard) = lock.try_lock_owned() else {
                        continue;
                    };
                    let Some(_lease) = store.try_refresh_lease(&candidate.operation_key).await?
                    else {
                        continue;
                    };
                    // Claim by advancing the journal revision, not just reading
                    // or checking it. Publication requires revision one: even if
                    // an operation loses its lease and resumes late, it can no
                    // longer publish a backing claimed for deletion. This also
                    // waits for any still-committing publication transaction.
                    let claim = Mutation::Put {
                        kind: CANDIDATE_KIND.to_string(),
                        key: key.clone(),
                        expected: Some(record.revision),
                        payload: record.payload,
                    };
                    let claimed = match store.commit(&[claim], &[]).await {
                        Ok(receipt) => receipt,
                        Err(error) if error.code() == tonic::Code::Aborted => continue,
                        Err(error) => return Err(error),
                    };
                    let revision = claimed.revisions[&(CANDIDATE_KIND.to_string(), key.clone())];
                    match self
                        .storage
                        .delete(
                            &scope,
                            &candidate.owner,
                            &candidate.purpose,
                            &candidate.backing,
                        )
                        .await
                    {
                        Ok(()) => {}
                        Err(error) if error.code() == tonic::Code::NotFound => {}
                        Err(_) => continue,
                    }
                    store
                        .commit(
                            &[Mutation::Delete {
                                kind: CANDIDATE_KIND.to_string(),
                                key,
                                expected: revision,
                            }],
                            &[],
                        )
                        .await?;
                }
            }
            let refs = self.repository.references(&scope);
            let mut after = None;
            loop {
                let page = store
                    .list(crate::repository::references::KIND, after.as_deref(), 128)
                    .await?;
                if page.is_empty() {
                    break;
                }
                for (key, record) in page {
                    after = Some(key.clone());
                    let state: ReferenceState = decode(&record.payload)?;
                    if scope.authorize_owner(&state.owner).is_err() {
                        continue;
                    }
                    for backing in &state.pending_deletions {
                        if !state.revoked && *backing == state.backing {
                            return Err(Status::data_loss(
                                "issuer live backing was marked for deletion",
                            ));
                        }
                        match self
                            .storage
                            .delete(&scope, &state.owner, VALUE_PURPOSE, backing)
                            .await
                        {
                            Ok(()) => {}
                            Err(error) if error.code() == tonic::Code::NotFound => {}
                            Err(_) => continue,
                        }
                        refs.registry()
                            .acknowledge_deletion(&key, &state.owner, backing)
                            .await?;
                    }
                }
            }
        }
        Ok(())
    }
}
