// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer-owned, stateless built-ins. They see no gateway records, references,
//! environment keys, scheduling state, or storage interfaces.

mod failure;
mod protocol;

use crate::minter::{
    MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, StrategyDescriptor,
    TokenMinter,
};
use async_trait::async_trait;
use protocol::{
    mint_aws_sts_assume_role, mint_google_service_account_jwt, mint_oauth2_client_credentials,
    mint_oauth2_refresh_token,
};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tonic::Status;

struct Input {
    token_url: String,
    scopes: Vec<String>,
    max_lifetime_seconds: i64,
    material: HashMap<String, String>,
    sts_endpoint: Option<String>,
}

type MintFuture<'a> = Pin<Box<dyn Future<Output = Result<MintResponse, MintFailure>> + Send + 'a>>;
type MintFn = for<'a> fn(&'a Input) -> MintFuture<'a>;

#[derive(Debug)]
struct BuiltinMinter {
    name: &'static str,
    primary_output: &'static str,
    additional_outputs: &'static [&'static str],
    config: &'static [&'static str],
    secret_material: &'static [&'static str],
    rotates_refresh_token: bool,
    allow_loopback_sts: bool,
    mint: MintFn,
}

#[async_trait]
impl TokenMinter for BuiltinMinter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: self.name.to_string(),
            config: self
                .config
                .iter()
                .copied()
                .chain(["token_url", "scope", "max_lifetime_seconds"])
                .map(|name| MaterialDescriptor {
                    name: name.to_string(),
                    required: false,
                })
                .collect(),
            secret_material: self
                .secret_material
                .iter()
                .map(|name| MaterialDescriptor {
                    name: (*name).to_string(),
                    required: false,
                })
                .collect(),
            outputs: std::iter::once(self.primary_output)
                .chain(self.additional_outputs.iter().copied())
                .map(str::to_string)
                .collect(),
            rotated_secret_material: if self.rotates_refresh_token {
                vec!["refresh_token".to_string()]
            } else {
                Vec::new()
            },
        }
    }

    async fn mint(&self, mut request: MintRequest) -> Result<MintResponse, MintFailure> {
        let token_url = request.config.remove("token_url").unwrap_or_default();
        let scopes = request.config.remove("scope").unwrap_or_default();
        let max_lifetime_seconds = request
            .config
            .remove("max_lifetime_seconds")
            .ok_or_else(|| Status::invalid_argument("missing mint lifetime"))?
            .parse::<i64>()
            .map_err(|_| Status::invalid_argument("invalid mint lifetime"))?;
        if max_lifetime_seconds <= 0 {
            return Err(Status::invalid_argument("invalid mint lifetime").into());
        }
        let sts_endpoint = if let Some(endpoint) = request.config.remove("sts_endpoint_url") {
            if !self.allow_loopback_sts || !is_loopback_http(&endpoint) {
                return Err(
                    Status::invalid_argument("STS endpoint overrides are not permitted").into(),
                );
            }
            Some(endpoint)
        } else {
            None
        };
        let mut material = request.config;
        material.extend(request.secret_material);
        let input = Input {
            token_url,
            scopes: scopes.split_whitespace().map(str::to_string).collect(),
            max_lifetime_seconds,
            material,
            sts_endpoint,
        };
        (self.mint)(&input).await
    }
}

fn is_loopback_http(endpoint: &str) -> bool {
    reqwest::Url::parse(endpoint).is_ok_and(|url| {
        url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1"))
    })
}

/// Registry used by embedded and standalone issuers. Production STS endpoints
/// are resolved from the region; no caller-supplied endpoint is honored.
#[must_use]
pub fn registry() -> MinterRegistry {
    build_registry(false)
}

/// Explicit test-only registry. Only the STS minter accepts an HTTP loopback
/// endpoint. Enabling the feature does not change `registry()` behavior.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub fn registry_with_loopback_sts_for_tests() -> MinterRegistry {
    build_registry(true)
}

fn build_registry(allow_loopback_sts: bool) -> MinterRegistry {
    let mut registry = MinterRegistry::default();
    for builtin in [
        BuiltinMinter {
            name: "oauth2_refresh_token",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_id", "tenant_id"],
            secret_material: &["refresh_token", "client_secret"],
            rotates_refresh_token: true,
            allow_loopback_sts: false,
            mint: |input| Box::pin(mint_oauth2_refresh_token(input)),
        },
        BuiltinMinter {
            name: "oauth2_client_credentials",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_id", "tenant_id"],
            secret_material: &["client_secret", "refresh_token"],
            rotates_refresh_token: true,
            allow_loopback_sts: false,
            mint: |input| Box::pin(mint_oauth2_client_credentials(input)),
        },
        BuiltinMinter {
            name: "google_service_account_jwt",
            primary_output: "access_token",
            additional_outputs: &[],
            config: &["client_email", "subject", "sub"],
            secret_material: &["private_key", "refresh_token"],
            rotates_refresh_token: true,
            allow_loopback_sts: false,
            mint: |input| Box::pin(mint_google_service_account_jwt(input)),
        },
        BuiltinMinter {
            name: "aws_sts_assume_role",
            primary_output: "access_key_id",
            additional_outputs: &["secret_access_key", "session_token"],
            config: &[
                "role_arn",
                "session_name",
                "external_id",
                "aws_region",
                "aws_access_key_id",
            ],
            secret_material: &["aws_secret_access_key", "aws_session_token"],
            rotates_refresh_token: false,
            allow_loopback_sts,
            mint: |input| Box::pin(mint_aws_sts_assume_role(input)),
        },
    ] {
        registry
            .register_builtin(Arc::new(builtin))
            .expect("built-in minter descriptors are valid and unique");
    }
    registry
}

#[cfg(test)]
mod tests;
