// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use futures::StreamExt;
use std::{
    convert::Infallible,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Poll,
};
use tonic::{body::Body, codegen::Bytes, service::AxumBody};
use tower::ServiceExt;

const TEST_TIMEOUT: Duration = Duration::from_secs(1);
const WATCHDOG: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum Stall {
    Body,
    Trailers,
}

#[derive(Default)]
struct Observation {
    requests: Mutex<Vec<(String, String)>>,
    data_frames: AtomicUsize,
    stalled: AtomicBool,
}

struct WireServer {
    channel: Channel,
    task: tokio::task::JoinHandle<()>,
    observation: Arc<Observation>,
    received: Arc<Mutex<Vec<wire::MintRequest>>>,
}

impl Drop for WireServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Return real gRPC response headers immediately, then stall at the selected
/// wire phase. Sleeping in a tonic handler would only exercise header timeout.
async fn start_stalled(method: &'static str, stall: Stall) -> WireServer {
    let observation = Arc::new(Observation::default());
    let received = Arc::new(Mutex::new(Vec::new()));
    let inner = wire::token_minter_server::TokenMinterServer::new(Fake {
        descriptor: descriptor(),
        response: Ok(response()),
        received: received.clone(),
    });
    let observed = observation.clone();
    let service = tower::service_fn(move |request: http::Request<Body>| {
        let inner = inner.clone();
        let observation = observed.clone();
        async move {
            let path = request.uri().path().to_string();
            let timeout = request
                .headers()
                .get("grpc-timeout")
                .map(|value| value.to_str().unwrap().to_string())
                .unwrap_or_default();
            observation
                .requests
                .lock()
                .unwrap()
                .push((path.clone(), timeout));
            let response = inner.oneshot(request).await?;
            if !path.ends_with(method) {
                return Ok::<_, Infallible>(response);
            }
            let pending_observation = observation.clone();
            let pending = futures::stream::poll_fn(move |_| {
                pending_observation.stalled.store(true, Ordering::SeqCst);
                Poll::<Option<Result<Bytes, Status>>>::Pending
            });
            let response = response.map(|body| match stall {
                Stall::Body => Body::new(AxumBody::from_stream(pending)),
                Stall::Trailers => {
                    // Forward the generated, correctly framed protobuf message
                    // but discard trailers and never end the HTTP/2 stream.
                    let data = AxumBody::new(body).into_data_stream().map(move |data| {
                        if data.is_ok() {
                            observation.data_frames.fetch_add(1, Ordering::SeqCst);
                        }
                        data.map_err(|_| Status::unknown("test response body failed"))
                    });
                    Body::new(AxumBody::from_stream(data.chain(pending)))
                }
            });
            Ok(response)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .serve_with_incoming(service, TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    WireServer {
        channel,
        task,
        observation,
        received,
    }
}

fn assert_stalled(server: &WireServer, stall: Stall, methods: &[&str]) {
    assert!(server.observation.stalled.load(Ordering::SeqCst));
    assert_eq!(
        server.observation.data_frames.load(Ordering::SeqCst) > 0,
        matches!(stall, Stall::Trailers),
        "trailer regression must send a complete protobuf message first"
    );
    let requests = server.observation.requests.lock().unwrap();
    assert_eq!(requests.len(), methods.len(), "RPCs must not be replayed");
    for ((path, timeout), method) in requests.iter().zip(methods) {
        assert!(path.ends_with(method));
        assert!(
            !timeout.is_empty(),
            "grpc-timeout metadata must be retained"
        );
    }
    let mut expected = tonic::Request::new(());
    expected.set_timeout(TEST_TIMEOUT);
    assert_eq!(
        requests.last().unwrap().1,
        expected
            .metadata()
            .get("grpc-timeout")
            .unwrap()
            .to_str()
            .unwrap()
    );
}

async fn discovery_stall_is_bounded(stall: Stall) {
    let server = start_stalled("/Describe", stall).await;
    let error = tokio::time::timeout(
        WATCHDOG,
        RemoteMinter::discover_with_timeout(server.channel.clone(), "test", TEST_TIMEOUT),
    )
    .await
    .expect("discovery must enforce its own full-RPC deadline")
    .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "remote minter discovery failed");
    assert!(error.details().is_empty());
    assert_stalled(&server, stall, &["/Describe"]);
    assert!(server.received.lock().unwrap().is_empty());
}

async fn mint_stall_is_parked_without_replay(stall: Stall) {
    let server = start_stalled("/Mint", stall).await;
    let minter = RemoteMinter::discover(server.channel.clone(), "test")
        .await
        .unwrap();
    let failure = tokio::time::timeout(WATCHDOG, minter.mint_with_timeout(request(), TEST_TIMEOUT))
        .await
        .expect("mint must enforce its own full-RPC deadline")
        .unwrap_err();
    assert_eq!(failure.status.code(), Code::FailedPrecondition);
    assert_eq!(
        failure.status.message(),
        "remote minter outcome is uncertain; investigate the attempt"
    );
    assert!(failure.status.details().is_empty());
    assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
    assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
    assert_eq!(failure.failure_code, "remote_minter_outcome_unknown");
    assert_eq!(failure.provider_error_subtype, None);
    for secret in ["input-secret", "minted-secret", "rotated-secret"] {
        assert!(!format!("{failure:?}").contains(secret));
    }
    assert_stalled(&server, stall, &["/Describe", "/Mint"]);
    let received = server.received.lock().unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].attempt_id, "durable-attempt");
}

#[tokio::test]
async fn discovery_deadline_covers_headers_first_stalled_body() {
    discovery_stall_is_bounded(Stall::Body).await;
}

#[tokio::test]
async fn discovery_deadline_covers_headers_first_stalled_trailers() {
    discovery_stall_is_bounded(Stall::Trailers).await;
}

#[tokio::test]
async fn mint_deadline_covers_headers_first_stalled_body_without_replay() {
    mint_stall_is_parked_without_replay(Stall::Body).await;
}

#[tokio::test]
async fn mint_deadline_covers_headers_first_stalled_trailers_without_replay() {
    mint_stall_is_parked_without_replay(Stall::Trailers).await;
}

#[tokio::test]
async fn completed_classified_failures_remain_sanitized_without_replay() {
    for (code, action, schedule, expected_action, expected_schedule, failure_code) in [
        (
            Code::Unavailable,
            wire::RecoveryAction::Retry,
            wire::RetrySchedule::Short,
            RecoveryAction::Retry,
            RetrySchedule::Short,
            "remote_minter_retry",
        ),
        (
            Code::InvalidArgument,
            wire::RecoveryAction::FixConfiguration,
            wire::RetrySchedule::Configuration,
            RecoveryAction::FixConfiguration,
            RetrySchedule::Configuration,
            "remote_minter_configuration",
        ),
        (
            Code::FailedPrecondition,
            wire::RecoveryAction::Reauthorize,
            wire::RetrySchedule::Parked,
            RecoveryAction::Reauthorize,
            RetrySchedule::Parked,
            "remote_minter_reauthorize",
        ),
        (
            Code::FailedPrecondition,
            wire::RecoveryAction::Investigate,
            wire::RetrySchedule::Parked,
            RecoveryAction::Investigate,
            RetrySchedule::Parked,
            "remote_minter_investigate",
        ),
    ] {
        let details = wire::MintFailureDetail {
            recovery_action: action as i32,
            retry_schedule: schedule as i32,
            failure_code: "secret-diagnostic".to_string(),
            provider_error_subtype: "secret-diagnostic".to_string(),
        };
        let received = Arc::new(Mutex::new(Vec::new()));
        let (channel, task) = start(Fake {
            descriptor: descriptor(),
            response: Err(Status::with_details(
                code,
                "secret-diagnostic",
                details.encode_to_vec().into(),
            )),
            received: received.clone(),
        })
        .await;
        let minter = RemoteMinter::discover_with_timeout(channel, "test", TEST_TIMEOUT)
            .await
            .unwrap();
        let failure = minter
            .mint_with_timeout(request(), TEST_TIMEOUT)
            .await
            .unwrap_err();
        assert_eq!(failure.status.code(), code);
        assert_eq!(failure.recovery_action, expected_action);
        assert_eq!(failure.retry_schedule, expected_schedule);
        assert_eq!(failure.failure_code, failure_code);
        assert!(failure.status.details().is_empty());
        assert!(!format!("{failure:?}").contains("secret-diagnostic"));
        assert_eq!(received.lock().unwrap().len(), 1);
        task.abort();
    }
}
