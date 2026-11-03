// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Keep generated issuer wire messages safe in generic Debug/Request logging.

use super::credentials::{minter::v1 as minter, refresh::v1 as refresh, store::v1 as store};

macro_rules! redacted_debug {
    ($($ty:path),+ $(,)?) => {$(
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($ty), "(<redacted>)"))
            }
        }
    )+};
}
redacted_debug!(
    store::PutSecretRequest,
    store::ResolvedSecret,
    refresh::CreateGrantRequest,
    refresh::InitializeGrantRequest,
    minter::MintRequest,
    minter::MintResponse
);

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::HashMap;

    #[test]
    fn wire_round_trips_preserve_values_but_debug_never_contains_them() {
        let secret = "never-log-issuer-secret";
        let request = minter::MintRequest {
            strategy: "custom:test".to_string(),
            attempt_id: "attempt".to_string(),
            config: HashMap::from([("endpoint".to_string(), secret.to_string())]),
            secret_material: HashMap::from([("token".to_string(), secret.to_string())]),
        };
        assert_eq!(
            minter::MintRequest::decode(request.encode_to_vec().as_slice()).unwrap(),
            request
        );
        let response = minter::MintResponse {
            outputs: HashMap::from([("access_token".to_string(), secret.to_string())]),
            rotated_secret_material: request.secret_material.clone(),
            expiration_time: None,
        };
        let create = refresh::CreateGrantRequest {
            config: request.config.clone(),
            secret_material: request.secret_material.clone(),
            ..Default::default()
        };
        let initialize = refresh::InitializeGrantRequest {
            config: request.config.clone(),
            secret_material: request.secret_material.clone(),
            ..Default::default()
        };
        assert_eq!(
            refresh::InitializeGrantRequest::decode(initialize.encode_to_vec().as_slice()).unwrap(),
            initialize
        );
        let put = store::PutSecretRequest {
            value: secret.to_string(),
            ..Default::default()
        };
        let resolved = store::ResolveSecretsResponse {
            secrets: vec![store::ResolvedSecret {
                value: secret.to_string(),
                ..Default::default()
            }],
        };
        for debug in [
            format!("{request:?}"),
            format!("{response:?}"),
            format!("{create:?}"),
            format!("{initialize:?}"),
            format!("{:?}", tonic::Request::new(initialize)),
            format!("{put:?}"),
            format!("{resolved:?}"),
            format!("{:?}", tonic::Request::new(request)),
        ] {
            assert!(!debug.contains(secret));
            assert!(debug.contains("redacted"));
        }
    }

    #[test]
    fn version_presence_and_watch_cursors_have_distinct_wire_identities() {
        let mut request = store::PutSecretRequest::default();
        assert_eq!(
            store::PutSecretRequest::decode(request.encode_to_vec().as_slice())
                .unwrap()
                .expected_version,
            None
        );
        request.expected_version = Some(0);
        assert_eq!(
            store::PutSecretRequest::decode(request.encode_to_vec().as_slice())
                .unwrap()
                .expected_version,
            Some(0)
        );
        let watch = store::WatchSecretsResponse {
            reference: "ref".to_string(),
            version: 12,
            sequence: 99,
            reset_required: false,
            revoked: true,
            checkpoint: false,
        };
        assert_eq!(
            store::WatchSecretsResponse::decode(watch.encode_to_vec().as_slice()).unwrap(),
            watch
        );
    }
}
