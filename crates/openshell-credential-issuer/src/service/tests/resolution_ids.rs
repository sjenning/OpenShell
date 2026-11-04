// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn resolution_correlation_ids_accept_the_full_provider_key_bound() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let stored = create(&runtime).await;
    for length in [129, 256] {
        for purpose in [
            wire::ResolvePurpose::SandboxDelivery,
            wire::ResolvePurpose::OperatorExport,
            wire::ResolvePurpose::Refresh,
            wire::ResolvePurpose::MetadataInspection,
        ] {
            let mut request = resolve(&stored.reference, purpose);
            let id = "K".repeat(length);
            request.secrets[0].request_id = id.clone();
            let response = runtime.resolve(&test_scope(A), request).await.unwrap();
            assert_eq!(response.secrets[0].request_id, id);
            assert_eq!(response.secrets[0].version, stored.version);
            assert_eq!(
                response.secrets[0].value,
                if purpose == wire::ResolvePurpose::MetadataInspection {
                    ""
                } else {
                    "private-value"
                }
            );
        }
    }
}

#[tokio::test]
async fn invalid_resolution_correlation_ids_reject_the_whole_batch_before_backend_reads() {
    let fixture = Fixture::new().await;
    let runtime = fixture.runtime();
    let stored = create(&runtime).await;
    let before = fixture.driver.resolves.load(Ordering::SeqCst);
    for id in [
        "K".repeat(257),
        String::new(),
        " padded".into(),
        "control\ncharacter".into(),
        "one".into(), // Duplicate of the otherwise-valid first sibling.
    ] {
        let mut request = resolve(&stored.reference, wire::ResolvePurpose::SandboxDelivery);
        let mut invalid = request.secrets[0].clone();
        invalid.request_id = id;
        request.secrets.push(invalid);
        assert_eq!(
            runtime
                .resolve(&test_scope(A), request)
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        assert_eq!(fixture.driver.resolves.load(Ordering::SeqCst), before);
    }
}
