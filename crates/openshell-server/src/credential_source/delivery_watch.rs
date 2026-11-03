// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Every replica observes its issuer watches and invalidates its local sessions.
use super::RemoteProviderSource;
use crate::ServerState;
use openshell_credential_issuer::remote_issuer::{IssuerChange, WatchHealth};
use std::sync::{Arc, Weak};
use tokio::sync::{broadcast, watch};
/// Keep this guard for the gateway lifetime. Dropping it cancels notification
/// forwarding, never issuer-admitted mutations or mint attempts.
#[derive(Debug)]
pub struct DeliveryWatch(tokio::task::JoinHandle<()>);
impl Drop for DeliveryWatch {
    fn drop(&mut self) {
        self.0.abort();
    }
}
/// Subscribe before serving sessions. Reconciliation recovery must publish even
/// when it discovers unchanged versions: builds attempted while Unknown failed.
pub fn spawn(state: &Arc<ServerState>, source: &RemoteProviderSource) -> DeliveryWatch {
    DeliveryWatch(tokio::spawn(run(
        Arc::downgrade(state),
        source.client.changes(),
        source.client.health_changes(),
    )))
}
async fn run(
    state: Weak<ServerState>,
    mut changes: broadcast::Receiver<IssuerChange>,
    mut health: watch::Receiver<WatchHealth>,
) {
    let mut previous = *health.borrow_and_update();
    if let Some(state) = state.upgrade() {
        crate::config_delivery::publish_all_local(&state);
    } else {
        return;
    }
    loop {
        let closed = tokio::select! {
            event=changes.recv()=>match event {Ok(_)|Err(broadcast::error::RecvError::Lagged(_))=>false,Err(broadcast::error::RecvError::Closed)=>true},
            result=health.changed()=> {
                if result.is_err() {true} else {
                    let current=*health.borrow_and_update();
                    if current==previous {continue;}
                    previous=current;false
                }
            },
        };
        let Some(state) = state.upgrade() else { return };
        // Unknown, reset, revocation, value/grant changes and consumer lag all
        // revoke the delivery assumption. The selected source remains the only
        // resolver, so rebuilding while Unknown cannot read stale local values.
        // Other replicas have independent watches; do not echo peer fanout.
        crate::config_delivery::publish_all_local(&state);
        if closed {
            return;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use openshell_credential_issuer::remote_issuer::ChangeKind;
    use std::time::Duration;
    async fn state() -> Arc<ServerState> {
        let mut state = crate::grpc::test_support::test_server_state().await;
        Arc::get_mut(&mut state)
            .unwrap()
            .config
            .config_delivery_mode = openshell_core::config::ConfigDeliveryMode::Push;
        state
    }
    async fn published(state: &ServerState, before: u64) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while state.config_delivery.publications() <= before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn changes_unknown_lag_and_reconciliation_recovery_invalidate_local_delivery() {
        let state = state().await;
        let (events, rx) = broadcast::channel(1);
        let (health, health_rx) = watch::channel(WatchHealth::default());
        // Overflow before starting the consumer to exercise lost notifications.
        events
            .send(IssuerChange::Unknown(ChangeKind::Secrets))
            .unwrap();
        events
            .send(IssuerChange::Unknown(ChangeKind::Grants))
            .unwrap();
        let guard = DeliveryWatch(tokio::spawn(run(Arc::downgrade(&state), rx, health_rx)));
        published(&state, 0).await;
        for event in [
            IssuerChange::Secret {
                reference: "reference".into(),
                version: 2,
                revoked: false,
            },
            IssuerChange::Grant {
                grant: "grant".into(),
                version: 3,
                deleted: true,
            },
            IssuerChange::Unknown(ChangeKind::Secrets),
        ] {
            let before = state.config_delivery.publications();
            events.send(event).unwrap();
            published(&state, before).await;
        }
        let before = state.config_delivery.publications();
        health.send_replace(WatchHealth {
            secrets: true,
            grants: true,
            generation: 1,
        });
        published(&state, before).await;
        drop(guard);
        tokio::task::yield_now().await;
        let before = state.config_delivery.publications();
        health.send_replace(WatchHealth::default());
        tokio::task::yield_now().await;
        assert_eq!(state.config_delivery.publications(), before);
    }
    #[tokio::test]
    async fn unchanged_health_updates_do_not_create_snapshot_rebuild_loops() {
        let state = state().await;
        let (_events, rx) = broadcast::channel(1);
        let (health, health_rx) = watch::channel(WatchHealth::default());
        let _guard = DeliveryWatch(tokio::spawn(run(Arc::downgrade(&state), rx, health_rx)));
        published(&state, 0).await;
        for _ in 0..4 {
            health.send_replace(WatchHealth::default());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(state.config_delivery.publications(), 1);
    }
    #[tokio::test]
    async fn authenticated_issuer_rotation_reaches_delivery_without_value_reads() {
        use crate::credential_source::{tests::issuer::Issuer, wire};
        use std::sync::atomic::Ordering;
        let state = state().await;
        let issuer = Issuer::start().await;
        let source = RemoteProviderSource::new("primary", issuer.watched.clone()).unwrap();
        let owner = wire::SecretOwner {
            workspace: "default".into(),
            provider_id: "provider".into(),
            credential_key: "TOKEN".into(),
            provider: "display".into(),
        };
        let first = issuer
            .watched
            .put_secret(wire::PutSecretRequest {
                owner: Some(owner.clone()),
                value: "first".into(),
                idempotency_key: "first".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        issuer
            .watched
            .wait_synchronized(Duration::from_secs(5))
            .await
            .unwrap();
        let before = state.config_delivery.publications();
        let _guard = spawn(&state, &source);
        published(&state, before).await;
        let before = state.config_delivery.publications();
        issuer
            .raw
            .put_secret(wire::PutSecretRequest {
                owner: Some(owner),
                reference: first.reference,
                expected_version: Some(first.version),
                value: "second".into(),
                idempotency_key: "second".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        published(&state, before).await;
        assert_eq!(issuer.resolves.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn closed_notification_channel_invalidates_and_stops_without_owning_state() {
        let state = state().await;
        let (events, rx) = broadcast::channel(1);
        let (_health, health_rx) = watch::channel(WatchHealth::default());
        let task = tokio::spawn(run(Arc::downgrade(&state), rx, health_rx));
        drop(events);
        task.await.unwrap();
        assert_eq!(state.config_delivery.publications(), 2);
        let (events, rx) = broadcast::channel(1);
        let (_health, health_rx) = watch::channel(WatchHealth::default());
        let weak = Arc::downgrade(&state);
        let task = tokio::spawn(run(weak.clone(), rx, health_rx));
        drop(state);
        assert!(weak.upgrade().is_none());
        let _ = events.send(IssuerChange::Unknown(ChangeKind::Secrets));
        task.await.unwrap();
    }
}
