// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn daemon_serves_opt_in_metrics_and_stops_listener_on_shutdown() {
    openshell_crypto::tls::ensure_default_provider();
    let mut fixture = Fixture::new().await;
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    fixture.config = fixture.config.replace(
        "refresh_interval_seconds =",
        &format!("metrics_bind_address = \"{address}\"\nrefresh_interval_seconds ="),
    );
    let (stop, task) = fixture.start().await;
    let client = RemoteIssuer::connect(&fixture.client).await.unwrap();
    client.list_strategies().await.unwrap();
    let response = reqwest::get(format!("http://{address}/metrics"))
        .await
        .unwrap();
    assert!(response.status().is_success());
    let body = response.text().await.unwrap();
    assert!(body.contains("openshell_issuer_operations_total"));
    assert!(body.contains("operation=\"list_strategies\""));
    assert!(!body.contains("spiffe://"));
    assert!(!body.contains("issuer.db"));
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}
