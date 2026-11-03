// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{
    convert::Infallible,
    future::{Ready, ready},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tonic::{
    Request, Response, Status,
    body::Body,
    server::{NamedService, ServerStreamingService},
};
use tower::Service;

// Minimal SPIFFE Workload API wire fixtures. Production uses the upstream
// client's parser; keeping these independent tests the actual wire boundary.
#[derive(Clone, PartialEq, prost::Message)]
struct FetchRequest {}
#[derive(Clone, PartialEq, prost::Message)]
struct Svid {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(bytes = "vec", tag = "2")]
    chain: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    bundle: Vec<u8>,
}
#[derive(Clone, PartialEq, prost::Message)]
struct FetchResponse {
    #[prost(message, repeated, tag = "1")]
    svids: Vec<Svid>,
}
#[derive(Clone)]
struct Workload(Arc<Mutex<Vec<Svid>>>);
impl NamedService for Workload {
    const NAME: &'static str = "SpiffeWorkloadAPI";
}
impl ServerStreamingService<FetchRequest> for Workload {
    type Response = FetchResponse;
    type ResponseStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<FetchResponse, Status>> + Send>>;
    type Future = Ready<Result<Response<Self::ResponseStream>, Status>>;
    fn call(&mut self, request: Request<FetchRequest>) -> Self::Future {
        assert_eq!(
            request.metadata().get("workload.spiffe.io").unwrap(),
            "true"
        );
        let response = FetchResponse {
            svids: self.0.lock().unwrap().clone(),
        };
        ready(Ok(Response::new(Box::pin(tokio_stream::iter([Ok(
            response,
        )])))))
    }
}
impl Service<http::Request<Body>> for Workload {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        assert_eq!(request.uri().path(), "/SpiffeWorkloadAPI/FetchX509SVID");
        let service = self.clone();
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::<
                FetchResponse,
                FetchRequest,
            >::default());
            Ok(grpc.server_streaming(service, request).await)
        })
    }
}
fn wire(svid: &X509Svid) -> Svid {
    Svid {
        id: svid.spiffe_id().to_string(),
        chain: svid
            .cert_chain()
            .iter()
            .flat_map(|cert| cert.as_bytes().iter().copied())
            .collect(),
        key: svid.private_key().as_bytes().to_vec(),
        bundle: Vec::new(),
    }
}
#[tokio::test]
async fn workload_socket_is_refetched_on_rotation_and_never_falls_back_to_another_identity() {
    let first = tests::svid("spiffe://test.example/gateway");
    let second = tests::svid("spiffe://test.example/gateway");
    let other = tests::svid("spiffe://test.example/other");
    let state = Arc::new(Mutex::new(vec![wire(&other), wire(&first)]));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workload.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let service = Workload(state.clone());
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
            .await
            .unwrap();
    });
    let source = super::super::ExtensionClientIdentity::Spiffe {
        endpoint: format!("unix://{}", path.display()),
        spiffe_id: "spiffe://test.example/gateway".to_string(),
    };
    let (chain, _) = source.load().await.unwrap();
    assert_eq!(chain[0].as_ref(), first.leaf().as_bytes());
    *state.lock().unwrap() = vec![wire(&second)];
    let (chain, _) = source.load().await.unwrap();
    assert_eq!(chain[0].as_ref(), second.leaf().as_bytes());
    *state.lock().unwrap() = vec![wire(&other)];
    assert!(source.load().await.is_err());
    state.lock().unwrap().clear();
    assert!(source.load().await.is_err());
    assert!(!format!("{source:?}").contains("test.example"));
    task.abort();
}
