// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Built-in upstream protocols. No gateway or persisted grant types.
use super::Input;
use crate::minter::{MintFailure, MintResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::Status;
use tracing::warn;
const DEFAULT_MAX_LIFETIME_SECONDS: i64 = 3600;
const MAX_OAUTH_ERROR_RESPONSE_BYTES: usize = 8 * 1024;
fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| {
            i64::try_from(value.as_millis()).unwrap_or(i64::MAX)
        })
}
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default, deserialize_with = "deserialize_optional_oauth_string")]
    error_subtype: Option<String>,
}

fn deserialize_optional_oauth_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(value.as_str().map(str::to_owned))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OAuthGrantKind {
    UserRefreshToken,
    NonInteractive,
}

#[derive(Debug, Serialize)]
struct GoogleServiceAccountClaims<'a> {
    iss: &'a str,
    scope: String,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<&'a str>,
}

pub(super) async fn mint_oauth2_refresh_token(state: &Input) -> Result<MintResponse, MintFailure> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let refresh_token = required_material(&state.material, "refresh_token")?;
    let mut form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        ("client_id".to_string(), client_id),
        ("refresh_token".to_string(), refresh_token),
    ];
    if let Some(client_secret) = material_value(&state.material, &["client_secret"]) {
        form.push(("client_secret".to_string(), client_secret));
    }
    let scope = state.scopes.clone().join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(
        &token_url,
        &form,
        state.max_lifetime_seconds,
        OAuthGrantKind::UserRefreshToken,
    )
    .await
}

pub(super) async fn mint_oauth2_client_credentials(
    state: &Input,
) -> Result<MintResponse, MintFailure> {
    let token_url = oauth2_token_url(state)?;
    let client_id = required_material(&state.material, "client_id")?;
    let client_secret = required_material(&state.material, "client_secret")?;
    let mut form = vec![
        ("grant_type".to_string(), "client_credentials".to_string()),
        ("client_id".to_string(), client_id),
        ("client_secret".to_string(), client_secret),
    ];
    let scope = state.scopes.clone().join(" ");
    if !scope.is_empty() {
        form.push(("scope".to_string(), scope));
    }

    request_token(
        &token_url,
        &form,
        state.max_lifetime_seconds,
        OAuthGrantKind::NonInteractive,
    )
    .await
}

pub(super) async fn mint_google_service_account_jwt(
    state: &Input,
) -> Result<MintResponse, MintFailure> {
    openshell_crypto::install_jwt_provider();
    let token_url = google_token_url(state);
    let client_email = required_material(&state.material, "client_email")?;
    let private_key = required_material(&state.material, "private_key")?;
    let scopes = state.scopes.clone();
    if scopes.is_empty() {
        return Err(Status::invalid_argument(
            "google_service_account_jwt requires at least one scope",
        )
        .into());
    }
    let now_ms = current_time_ms();
    let now_secs = now_ms / 1000;
    let lifetime_secs = state.max_lifetime_seconds.min(DEFAULT_MAX_LIFETIME_SECONDS);
    let subject = material_value(&state.material, &["subject", "sub"]);
    let claims = GoogleServiceAccountClaims {
        iss: &client_email,
        scope: scopes.join(" "),
        aud: &token_url,
        iat: now_secs,
        exp: now_secs.saturating_add(lifetime_secs),
        sub: subject.as_deref(),
    };
    let assertion = openshell_crypto::jwt::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|_| {
            Status::invalid_argument("google_service_account_jwt private_key must be RSA PEM")
        })?,
    )
    .map_err(|_| Status::internal("sign google service account jwt failed"))?;
    let form = vec![
        (
            "grant_type".to_string(),
            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_string(),
        ),
        ("assertion".to_string(), assertion),
    ];
    request_token(
        &token_url,
        &form,
        lifetime_secs,
        OAuthGrantKind::NonInteractive,
    )
    .await
}

pub(super) async fn mint_aws_sts_assume_role(state: &Input) -> Result<MintResponse, MintFailure> {
    let role_arn = required_material(&state.material, "role_arn")?;
    let session_name = material_value(&state.material, &["session_name"])
        .unwrap_or_else(|| "openshell-sandbox".to_string());
    let external_id = material_value(&state.material, &["external_id"]);
    let region =
        material_value(&state.material, &["aws_region"]).unwrap_or_else(|| "us-east-1".to_string());

    let region_provider = aws_sdk_sts::config::Region::new(region);
    let mut config_loader =
        aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region_provider);

    // Explicit source credentials are all-or-nothing. A lone key must not
    // silently fall through to the issuer's ambient identity (CWE-20): the
    // caller asked for a specific principal, so an incomplete pair is an error.
    // An optional session token supports temporary source credentials (SSO or a
    // prior AssumeRole); it requires the access/secret pair.
    let session_token = material_value(&state.material, &["aws_session_token"]);
    match (
        material_value(&state.material, &["aws_access_key_id"]),
        material_value(&state.material, &["aws_secret_access_key"]),
    ) {
        (Some(access_key), Some(secret_key)) => {
            let creds = aws_sdk_sts::config::Credentials::new(
                access_key,
                secret_key,
                session_token,
                None,
                "openshell-provider-refresh",
            );
            config_loader = config_loader.credentials_provider(creds);
        }
        (None, None) if session_token.is_some() => {
            return Err(Status::invalid_argument(
                "aws_session_token requires aws_access_key_id and aws_secret_access_key",
            )
            .into());
        }
        (None, None) => {}
        _ => {
            return Err(Status::invalid_argument(
                "aws_access_key_id and aws_secret_access_key must both be set or both omitted",
            )
            .into());
        }
    }

    let sdk_config = config_loader.load().await;
    let sts_config = {
        let mut builder = aws_sdk_sts::config::Builder::from(&sdk_config);
        // Endpoint overrides exist only to point tests at a local mock STS. In
        // production the endpoint is always resolved from the region so a caller
        // cannot redirect an AWS-signed AssumeRole request at an arbitrary
        // service (CWE-918). Only the explicit test registry can set this field.
        if let Some(endpoint) = &state.sts_endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        builder.build()
    };
    let client = aws_sdk_sts::Client::from_conf(sts_config);

    let max_lifetime_i64 = state.max_lifetime_seconds;
    let max_lifetime = i32::try_from(max_lifetime_i64.min(i64::from(i32::MAX))).unwrap_or(i32::MAX);
    let max_lifetime_ms = i64::from(max_lifetime).saturating_mul(1000);

    let mut req = client
        .assume_role()
        .role_arn(&role_arn)
        .role_session_name(&session_name)
        .duration_seconds(max_lifetime);

    if let Some(eid) = external_id {
        req = req.external_id(eid);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| Status::internal(format!("STS AssumeRole failed: {e}")))?;

    let creds = resp
        .credentials()
        .ok_or_else(|| Status::internal("STS AssumeRole response missing credentials"))?;

    let access_key_id = creds.access_key_id().to_string();
    let secret_access_key = creds.secret_access_key().to_string();
    let session_token = creds.session_token().to_string();

    let now_ms = current_time_ms();
    let max_expires = now_ms.saturating_add(max_lifetime_ms);
    let expires_at_ms = creds.expiration().to_millis().unwrap_or(max_expires);
    let expires_at_ms = expires_at_ms.min(max_expires);

    Ok(MintResponse {
        outputs: HashMap::from([
            ("access_key_id".to_string(), access_key_id),
            ("secret_access_key".to_string(), secret_access_key),
            ("session_token".to_string(), session_token),
        ]),
        expiration_time_ms: expires_at_ms,
        rotated_secret_material: HashMap::new(),
    })
}

async fn request_token(
    token_url: &str,
    form: &[(String, String)],
    max_lifetime_seconds: i64,
    grant_kind: OAuthGrantKind,
) -> Result<MintResponse, MintFailure> {
    let parsed = reqwest::Url::parse(token_url)
        .map_err(|_| Status::invalid_argument("token_url must be an absolute URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if parsed.host_str().is_some_and(is_loopback_host) => {}
        _ => {
            return Err(Status::invalid_argument(
                "token_url must use https, except loopback http for local tests",
            )
            .into());
        }
    }

    openshell_crypto::tls::ensure_default_provider();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Status::internal(format!("build refresh HTTP client failed: {e}")))?;
    // GitHub returns form-encoded bodies unless JSON is requested.
    let response = client
        .post(parsed)
        .header(reqwest::header::ACCEPT, "application/json")
        .form(form)
        .send()
        .await
        .map_err(|error| {
            let error_kind = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connect"
            } else if error.is_request() {
                "request"
            } else {
                "other"
            };
            warn!(
                error = %error.without_url(),
                error_kind,
                "OAuth token endpoint request failed"
            );
            if grant_kind == OAuthGrantKind::UserRefreshToken && error_kind != "connect" {
                MintFailure::reauthorize(
                    Status::failed_precondition(
                        "refresh token exchange has an uncertain outcome; reauthorize the grant",
                    ),
                    "oauth_refresh_exchange_uncertain",
                    None,
                )
            } else {
                MintFailure::retryable(
                    Status::unavailable("token endpoint request failed"),
                    "oauth_token_endpoint_unavailable",
                )
            }
        })?;
    let status = response.status();
    if !status.is_success() {
        let body = read_bounded_oauth_error_body(response).await;
        return Err(classify_oauth_token_error(status, &body, grant_kind));
    }
    let token = response.json::<TokenResponse>().await.map_err(|_| {
        if grant_kind == OAuthGrantKind::UserRefreshToken {
            return MintFailure::reauthorize(
                Status::failed_precondition(
                    "refresh token exchange returned an unusable response; reauthorize the grant",
                ),
                "oauth_refresh_exchange_uncertain",
                None,
            );
        }
        MintFailure::investigate(
            Status::failed_precondition("token endpoint returned invalid JSON"),
            "oauth_invalid_success_response",
        )
    })?;
    if token.access_token.trim().is_empty() {
        if grant_kind == OAuthGrantKind::UserRefreshToken {
            return Err(MintFailure::reauthorize(
                Status::failed_precondition(
                    "refresh token exchange returned no access token; reauthorize the grant",
                ),
                "oauth_refresh_exchange_uncertain",
                None,
            ));
        }
        return Err(MintFailure::investigate(
            Status::failed_precondition("token endpoint returned empty access_token"),
            "oauth_empty_access_token",
        ));
    }
    let now_ms = current_time_ms();
    let lifetime_cap_seconds = if max_lifetime_seconds > 0 {
        max_lifetime_seconds
    } else {
        DEFAULT_MAX_LIFETIME_SECONDS
    };
    let lifetime_seconds = token
        .expires_in
        .filter(|value| *value > 0)
        .unwrap_or(lifetime_cap_seconds);
    let lifetime_seconds = lifetime_seconds.min(lifetime_cap_seconds);
    Ok(MintResponse {
        outputs: HashMap::from([("access_token".to_string(), token.access_token)]),
        expiration_time_ms: now_ms.saturating_add(lifetime_seconds.saturating_mul(1000)),
        rotated_secret_material: token
            .refresh_token
            .filter(|value| !value.trim().is_empty())
            .map(|value| HashMap::from([("refresh_token".to_string(), value)]))
            .unwrap_or_default(),
    })
}

async fn read_bounded_oauth_error_body(mut response: reqwest::Response) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < MAX_OAUTH_ERROR_RESPONSE_BYTES {
        let Ok(Some(chunk)) = response.chunk().await else {
            break;
        };
        let remaining = MAX_OAUTH_ERROR_RESPONSE_BYTES.saturating_sub(body.len());
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() >= remaining {
            break;
        }
    }
    body
}

fn classify_oauth_token_error(
    status: reqwest::StatusCode,
    body: &[u8],
    grant_kind: OAuthGrantKind,
) -> MintFailure {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return MintFailure::retryable(
            Status::unavailable(format!("token endpoint returned HTTP {status}")),
            "oauth_token_endpoint_retryable",
        );
    }

    let Ok(error_response) = serde_json::from_slice::<OAuthErrorResponse>(body) else {
        return MintFailure::investigate(
            Status::failed_precondition(format!(
                "token endpoint returned HTTP {status} without a recognized OAuth error"
            )),
            "oauth_unrecognized_error_response",
        );
    };

    match error_response.error.as_str() {
        "invalid_grant" if grant_kind == OAuthGrantKind::UserRefreshToken => {
            let subtype = error_response
                .error_subtype
                .as_deref()
                .filter(|subtype| *subtype == "invalid_rapt")
                .map(|_| "invalid_rapt");
            let message = if subtype.is_some() {
                "OAuth refresh grant requires interactive reauthorization (invalid_grant/invalid_rapt)"
            } else {
                "OAuth refresh grant is no longer usable (invalid_grant); user reauthorization is required"
            };
            MintFailure::reauthorize(
                Status::failed_precondition(message),
                "oauth_invalid_grant",
                subtype,
            )
        }
        "invalid_client" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the client configuration (invalid_client)",
            ),
            "oauth_invalid_client",
        ),
        "unauthorized_client" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the client grant (unauthorized_client)",
            ),
            "oauth_unauthorized_client",
        ),
        "invalid_scope" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the configured scopes (invalid_scope)",
            ),
            "oauth_invalid_scope",
        ),
        "unsupported_grant_type" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the configured grant type (unsupported_grant_type)",
            ),
            "oauth_unsupported_grant_type",
        ),
        "admin_policy_enforced" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth access is blocked by an administrator policy (admin_policy_enforced)",
            ),
            "oauth_admin_policy_enforced",
        ),
        "access_denied"
            if error_response.error_subtype.as_deref() == Some("admin_policy_enforced") =>
        {
            MintFailure::fix_configuration_with_subtype(
                Status::failed_precondition(
                    "OAuth access is blocked by an administrator policy (access_denied/admin_policy_enforced)",
                ),
                "oauth_admin_policy_enforced",
                "admin_policy_enforced",
            )
        }
        "access_denied" if grant_kind == OAuthGrantKind::UserRefreshToken => {
            MintFailure::reauthorize(
                Status::failed_precondition(
                    "OAuth access was denied; user reauthorization is required (access_denied)",
                ),
                "oauth_access_denied",
                None,
            )
        }
        "access_denied" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth access was denied for the non-interactive grant (access_denied)",
            ),
            "oauth_access_denied",
        ),
        "invalid_grant" => MintFailure::fix_configuration(
            Status::failed_precondition(
                "OAuth token endpoint rejected the non-interactive grant (invalid_grant)",
            ),
            "oauth_invalid_grant",
        ),
        "server_error" | "temporarily_unavailable" => MintFailure::retryable(
            Status::unavailable("OAuth token endpoint reported a temporary failure"),
            "oauth_token_endpoint_retryable",
        ),
        _ => MintFailure::investigate(
            Status::failed_precondition(format!(
                "token endpoint returned HTTP {status} with an unrecognized OAuth error"
            )),
            "oauth_unrecognized_error",
        ),
    }
}

fn oauth2_token_url(state: &Input) -> Result<String, Status> {
    if let Some(tenant_id) = material_value(&state.material, &["tenant_id"]) {
        return Ok(format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        ));
    }
    if !state.token_url.trim().is_empty() {
        return Ok(state.token_url.clone());
    }
    Err(Status::invalid_argument(
        "oauth2_client_credentials requires token_url or tenant_id material",
    ))
}

fn google_token_url(state: &Input) -> String {
    if state.token_url.trim().is_empty() {
        "https://oauth2.googleapis.com/token".to_string()
    } else {
        state.token_url.clone()
    }
}

fn required_material(material: &HashMap<String, String>, key: &str) -> Result<String, Status> {
    material_value(material, &[key])
        .ok_or_else(|| Status::invalid_argument(format!("{key} material is required")))
}

fn material_value(material: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = material.get(*key).map(|value| value.trim())
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests;
