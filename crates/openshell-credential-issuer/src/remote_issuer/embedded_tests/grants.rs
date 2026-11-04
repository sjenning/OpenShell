// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::{MintFailure, MintRequest, MintResponse, StrategyDescriptor, TokenMinter};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Debug, Default)]
struct Minter(AtomicUsize);
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:embedded-test".into(),
            config: vec![],
            secret_material: vec![],
            outputs: vec!["token".into()],
            rotated_secret_material: vec![],
        }
    }
    async fn mint(&self, _: MintRequest) -> Result<MintResponse, MintFailure> {
        let version = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Ok(MintResponse {
            outputs: HashMap::from([("token".into(), format!("token-{version}"))]),
            expiration_time_ms: i64::try_from(now.as_millis()).unwrap() + 60_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}

#[tokio::test]
async fn embedded_grant_reservation_initialization_refresh_rotation_and_detach_share_handlers() {
    let minter = Arc::new(Minter::default());
    let mut minters = MinterRegistry::default();
    minters.register_custom(minter.clone()).unwrap();
    let fixture = Fixture::with_minters(minters).await;
    let client = fixture.client().await;
    let mut watch = client.watch_grants(0).await.unwrap();
    assert!(watch.message().await.unwrap().unwrap().reset_required);
    assert!(watch.message().await.unwrap().unwrap().checkpoint);
    let reservation = refresh::ReserveGrantRequest {
        owner: Some(owner()),
        strategy: "custom:embedded-test".into(),
        outputs: HashMap::from([("token".into(), "TOKEN".into())]),
        refresh_before: Some(prost_types::Duration::default()),
        max_lifetime: Some(prost_types::Duration {
            seconds: 60,
            nanos: 0,
        }),
        idempotency_key: "reserve-grant".into(),
    };
    let reserved = client.reserve_grant(reservation.clone()).await.unwrap();
    assert_eq!(client.reserve_grant(reservation).await.unwrap(), reserved);
    assert_eq!(minter.0.load(Ordering::SeqCst), 0);
    let reference = &reserved.output_references["token"];
    assert_eq!(
        client
            .resolve_secrets(resolve(reference))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    let initialized = client
        .initialize_grant(refresh::InitializeGrantRequest {
            grant: reserved.grant.clone(),
            config: HashMap::new(),
            secret_material: HashMap::new(),
            idempotency_key: "initialize".into(),
        })
        .await
        .unwrap();
    assert_eq!(initialized.status.unwrap().state, "pending");
    let refreshed = client
        .ensure_fresh(refresh::EnsureFreshRequest {
            grant: reserved.grant.clone(),
            min_remaining: None,
        })
        .await
        .unwrap();
    assert_eq!(refreshed.status.unwrap().state, "refreshed");
    let first = client.resolve_secrets(resolve(reference)).await.unwrap();
    assert_eq!(first.secrets[0].value, "token-1");
    assert_eq!(first.secrets[0].version, 2);
    let rotation = refresh::RotateGrantRequest {
        grant: reserved.grant.clone(),
        idempotency_key: "rotate".into(),
    };
    let rotated = client.rotate_grant(rotation.clone()).await.unwrap();
    assert_eq!(client.rotate_grant(rotation).await.unwrap(), rotated);
    assert_eq!(minter.0.load(Ordering::SeqCst), 2);
    let second = client.resolve_secrets(resolve(reference)).await.unwrap();
    assert_eq!(second.secrets[0].value, "token-2");
    assert_eq!(second.secrets[0].version, 3);
    let detach = refresh::DetachGrantRequest {
        grant: reserved.grant.clone(),
        idempotency_key: "detach".into(),
    };
    client.detach_grant(detach.clone()).await.unwrap();
    client.detach_grant(detach).await.unwrap();
    assert_eq!(
        client
            .get_grant(refresh::GetGrantRequest {
                grant: reserved.grant.clone()
            })
            .await
            .unwrap()
            .status
            .unwrap()
            .state,
        "detached"
    );
    let detached = client.resolve_secrets(resolve(reference)).await.unwrap();
    assert_eq!(detached.secrets[0].value, second.secrets[0].value);
    assert_eq!(detached.secrets[0].version, second.secrets[0].version);
    assert_eq!(
        detached.secrets[0].expiration_time,
        second.secrets[0].expiration_time
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = watch.message().await.unwrap().unwrap();
            if event.grant == reserved.grant && event.deleted {
                break;
            }
        }
    })
    .await
    .unwrap();
}
