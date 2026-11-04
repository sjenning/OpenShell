// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Issuer telemetry with a closed label vocabulary and value-free OCSF audit.
//!
//! Never pass values, backing handles, hashes, request/debug dumps, or upstream
//! messages here. Operations and status codes are enums, not caller labels.
use crate::repository::grants::GrantPhase;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use openshell_ocsf::{
    ActionId, ApiActivityBuilder, DispositionId, EventContext, EventOrigin, ResourceDetails,
    SeverityId, StatusId, User, ocsf_emit,
};
use std::{future::Future, net::SocketAddr, sync::LazyLock, time::Instant};
use tonic::{Code, Status};

/// Closed operation vocabulary, shared by the embedded and standalone issuer.
#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Authenticate,
    GetCapabilities,
    ReserveSecret,
    PutSecret,
    ResolveSecrets,
    DeleteSecret,
    WatchSecrets,
    ListStrategies,
    CreateGrant,
    ReserveGrant,
    InitializeGrant,
    GetGrant,
    DeleteGrant,
    DetachGrant,
    RotateGrant,
    EnsureFresh,
    WatchGrants,
    Refresh,
    Scheduler,
    Cleanup,
}
impl Operation {
    fn label(self) -> &'static str {
        match self {
            Self::Authenticate => "authenticate",
            Self::GetCapabilities => "get_capabilities",
            Self::ReserveSecret => "reserve_secret",
            Self::PutSecret => "put_secret",
            Self::ResolveSecrets => "resolve_secrets",
            Self::DeleteSecret => "delete_secret",
            Self::WatchSecrets => "watch_secrets",
            Self::ListStrategies => "list_strategies",
            Self::CreateGrant => "create_grant",
            Self::ReserveGrant => "reserve_grant",
            Self::InitializeGrant => "initialize_grant",
            Self::GetGrant => "get_grant",
            Self::DeleteGrant => "delete_grant",
            Self::DetachGrant => "detach_grant",
            Self::RotateGrant => "rotate_grant",
            Self::EnsureFresh => "ensure_fresh",
            Self::WatchGrants => "watch_grants",
            Self::Refresh => "refresh",
            Self::Scheduler => "scheduler",
            Self::Cleanup => "cleanup",
        }
    }
    fn audited(self) -> bool {
        !matches!(
            self,
            Self::GetCapabilities
                | Self::ResolveSecrets
                | Self::WatchSecrets
                | Self::ListStrategies
                | Self::GetGrant
                | Self::WatchGrants
                | Self::Scheduler
                | Self::Cleanup
        )
    }
}

/// Measure a complete service operation without inspecting its request/result.
///
/// Failed access always produces a sanitized denial audit, including reads.
/// A cancelled future decrements in-flight and records a cancelled outcome.
pub async fn observe<T>(
    operation: Operation,
    future: impl Future<Output = Result<T, Status>>,
) -> Result<T, Status> {
    let guard = Observation::new(operation);
    let result = future.await;
    guard.finish(result.as_ref().err().map_or(Code::Ok, Status::code));
    result
}
struct Observation {
    operation: Operation,
    started: Instant,
    finished: bool,
}
impl Observation {
    fn new(operation: Operation) -> Self {
        gauge!("openshell_issuer_operations_in_flight", "operation" => operation.label())
            .increment(1.0);
        Self {
            operation,
            started: Instant::now(),
            finished: false,
        }
    }
    fn finish(mut self, code: Code) {
        let operation = self.operation.label();
        let outcome = if code == Code::Ok {
            "success"
        } else {
            "failure"
        };
        counter!("openshell_issuer_operations_total", "operation" => operation, "outcome" => outcome).increment(1);
        if code != Code::Ok {
            counter!("openshell_issuer_operation_failures_total", "operation" => operation, "code" => code_label(code)).increment(1);
        }
        if matches!(code, Code::PermissionDenied | Code::Unauthenticated) {
            counter!("openshell_issuer_access_denied_total", "operation" => operation, "code" => code_label(code)).increment(1);
        }
        if self.operation.audited()
            || matches!(code, Code::PermissionDenied | Code::Unauthenticated)
        {
            audit(self.operation, code);
        }
        self.finished = true;
    }
}
impl Drop for Observation {
    fn drop(&mut self) {
        let operation = self.operation.label();
        gauge!("openshell_issuer_operations_in_flight", "operation" => operation).decrement(1.0);
        histogram!("openshell_issuer_operation_duration_seconds", "operation" => operation)
            .record(self.started.elapsed().as_secs_f64());
        if !self.finished {
            counter!("openshell_issuer_operations_total", "operation" => operation, "outcome" => "cancelled").increment(1);
        }
    }
}
fn code_label(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}
static AUDIT_CONTEXT: LazyLock<EventContext> = LazyLock::new(|| EventContext {
    sandbox_id: String::new(),
    sandbox_name: String::new(),
    container_image: String::new(),
    hostname: String::new(),
    product_version: env!("CARGO_PKG_VERSION").into(),
    proxy_ip: std::net::Ipv4Addr::LOCALHOST.into(),
    proxy_port: 0,
    origin: EventOrigin::Gateway {
        name: "credential-issuer".into(),
    },
});
fn audit(operation: Operation, code: Code) {
    ocsf_emit!(audit_event(operation, code));
}
/// Record a TLS rejection without certificate bytes, peer-supplied identity,
/// verifier diagnostics, or any other untrusted metadata.
pub(crate) fn authentication_denied() {
    counter!("openshell_issuer_access_denied_total", "operation" => "authenticate", "code" => "unauthenticated").increment(1);
    audit(Operation::Authenticate, Code::Unauthenticated);
}
/// Audit a committed store mutation.
///
/// Supply only the authenticated scope, validated immutable owner, and
/// issuer-generated logical reference (never a physical driver handle or a
/// request fingerprint). Replay is safe to audit.
pub fn audit_store_mutation(
    operation: Operation,
    scope: &crate::auth::GatewayScope,
    owner: &crate::SecretOwner,
    reference: &str,
) {
    if !matches!(
        operation,
        Operation::ReserveSecret | Operation::PutSecret | Operation::DeleteSecret
    ) || scope.authorize_owner(owner).is_err()
        || reference.is_empty()
        || reference.len() > 256
        || reference.chars().any(char::is_control)
    {
        return;
    }
    ocsf_emit!(
        ApiActivityBuilder::new(&*AUDIT_CONTEXT, operation.label())
            .actor_user(User::other(scope.identity(), "Gateway"))
            .resource(ResourceDetails::new("issuer_reference", reference))
            .resource(ResourceDetails::named("workspace", &owner.workspace))
            .status(StatusId::Success)
            .message("Issuer secret mutation committed")
            .unmapped("component", "credential_issuer")
            .build()
    );
}
fn audit_event(operation: Operation, code: Code) -> openshell_ocsf::events::OcsfEvent {
    let denied = matches!(code, Code::PermissionDenied | Code::Unauthenticated);
    ApiActivityBuilder::new(&*AUDIT_CONTEXT, operation.label())
        .actor_user(User::unidentified())
        .status(if code == Code::Ok {
            StatusId::Success
        } else {
            StatusId::Failure
        })
        .severity(if denied {
            SeverityId::Medium
        } else if code == Code::Ok {
            SeverityId::Informational
        } else {
            SeverityId::Low
        })
        .action(if denied {
            ActionId::Denied
        } else {
            ActionId::Allowed
        })
        .disposition(if denied {
            DispositionId::Blocked
        } else {
            DispositionId::Allowed
        })
        .status_detail(code_label(code))
        .message(if denied {
            "Issuer access denied"
        } else {
            "Issuer operation completed"
        })
        .unmapped("component", "credential_issuer")
        .build()
}

pub(crate) const PHASES: [GrantPhase; 10] = [
    GrantPhase::Reserved,
    GrantPhase::Pending,
    GrantPhase::Refreshing,
    GrantPhase::Publishing,
    GrantPhase::Refreshed,
    GrantPhase::Failed,
    GrantPhase::Parked,
    GrantPhase::Deleting,
    GrantPhase::Deleted,
    GrantPhase::Detached,
];
pub(crate) fn phase_label(phase: GrantPhase) -> &'static str {
    match phase {
        GrantPhase::Reserved => "reserved",
        GrantPhase::Pending => "pending",
        GrantPhase::Refreshing => "refreshing",
        GrantPhase::Publishing => "publishing",
        GrantPhase::Refreshed => "refreshed",
        GrantPhase::Failed => "failed",
        GrantPhase::Parked => "parked",
        GrantPhase::Deleting => "deleting",
        GrantPhase::Deleted => "deleted",
        GrantPhase::Detached => "detached",
    }
}
/// Call only after a durable observable status change, not during preparation.
pub(crate) fn grant_transition(
    scope: &crate::auth::GatewayScope,
    state: &crate::repository::grants::GrantState,
) {
    let phase = state.phase;
    counter!("openshell_issuer_grant_transitions_total", "phase" => phase_label(phase))
        .increment(1);
    let failed = matches!(phase, GrantPhase::Failed | GrantPhase::Parked);
    ocsf_emit!(
        ApiActivityBuilder::new(&*AUDIT_CONTEXT, "grant_transition")
            .actor_user(User::other(scope.identity(), "Gateway"))
            .resource(ResourceDetails::new(
                "issuer_grant",
                &state.definition.identity.id
            ))
            .resource(ResourceDetails::named(
                "workspace",
                &state.definition.identity.owner.workspace
            ))
            .status(if failed {
                StatusId::Failure
            } else {
                StatusId::Success
            })
            .severity(if phase == GrantPhase::Parked {
                SeverityId::High
            } else if failed {
                SeverityId::Low
            } else {
                SeverityId::Informational
            })
            .message("Issuer grant status committed")
            .unmapped("component", "credential_issuer")
            .unmapped("phase", phase_label(phase))
            .build()
    );
}
pub(crate) fn cleanup_deferred(code: Code) {
    counter!("openshell_issuer_cleanup_deferred_total", "code" => code_label(code)).increment(1);
}
/// Publish only a complete, authorized sweep; partial/failed scans must not
/// replace the last successful snapshot with misleading zero counts.
// Metrics are approximate floating-point observations, not durable integers.
#[allow(clippy::cast_precision_loss)]
pub(crate) fn scheduler_snapshot(counts: &[u64; 10], now_ms: i64) {
    for (phase, count) in PHASES.into_iter().zip(counts) {
        gauge!("openshell_issuer_grants", "phase" => phase_label(phase)).set(*count as f64);
    }
    gauge!("openshell_issuer_scheduler_last_success_timestamp_seconds").set(now_ms as f64 / 1000.0);
}

/// Owns the maintained exporter's HTTP listener; dropping it stops serving.
pub(crate) struct MetricsExporter(tokio::task::JoinHandle<()>);
impl Drop for MetricsExporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(crate) fn start_exporter(address: SocketAddr) -> Result<MetricsExporter, Status> {
    let (recorder, exporter) = prometheus_builder()?
        .with_http_listener(address)
        .build()
        .map_err(|_| Status::unavailable("issuer metrics listener could not bind"))?;
    metrics::set_global_recorder(recorder)
        .map_err(|_| Status::failed_precondition("issuer metrics recorder is already installed"))?;
    describe_metrics();
    Ok(MetricsExporter(tokio::spawn(async move {
        if exporter.await.is_err() {
            tracing::error!("issuer metrics exporter stopped");
        }
    })))
}

fn prometheus_builder() -> Result<PrometheusBuilder, Status> {
    PrometheusBuilder::new()
        .set_buckets(&[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 120.0])
        .map_err(|_| Status::internal("issuer metrics histogram configuration invalid"))
}
fn describe_metrics() {
    metrics::describe_counter!(
        "openshell_issuer_operations_total",
        "Issuer operations by bounded operation and outcome"
    );
    metrics::describe_counter!(
        "openshell_issuer_operation_failures_total",
        "Issuer failures by bounded operation and gRPC code"
    );
    metrics::describe_counter!(
        "openshell_issuer_access_denied_total",
        "Issuer authentication and authorization denials"
    );
    metrics::describe_counter!(
        "openshell_issuer_grant_transitions_total",
        "Committed issuer grant status changes by resulting phase"
    );
    metrics::describe_counter!(
        "openshell_issuer_cleanup_deferred_total",
        "Physical cleanup failures retained durably for a later sweep"
    );
    metrics::describe_gauge!(
        "openshell_issuer_operations_in_flight",
        "Issuer operations currently in flight"
    );
    metrics::describe_gauge!(
        "openshell_issuer_grants",
        "Grant phase counts from the last completed scheduler sweep"
    );
    metrics::describe_gauge!(
        "openshell_issuer_scheduler_last_success_timestamp_seconds",
        "Unix time of the last completed issuer scheduler sweep"
    );
    metrics::describe_histogram!(
        "openshell_issuer_operation_duration_seconds",
        metrics::Unit::Seconds,
        "Issuer operation duration, including coordination and persistence"
    );
}

/// Only upstream classifications explicitly recognized by the built-in minter
/// may cross persistence/wire boundaries. No syntax-only allowlists.
#[must_use]
pub fn recognized_provider_error_subtype(
    failure_code: &str,
    subtype: &str,
) -> Option<&'static str> {
    match (failure_code, subtype) {
        ("oauth_invalid_grant", "invalid_rapt") => Some("invalid_rapt"),
        ("oauth_admin_policy_enforced", "admin_policy_enforced") => Some("admin_policy_enforced"),
        _ => None,
    }
}
/// Public error prose is generated from classification, never from a remote
/// Status message, minter body, stored secret, or private diagnostic.
#[must_use]
pub fn safe_error_message(failure_code: &str) -> &'static str {
    match failure_code {
        "" => "",
        "oauth_invalid_grant" => {
            "Credential authorization is no longer valid; reauthorize the provider."
        }
        "oauth_refresh_exchange_uncertain"
        | "mint_outcome_unknown"
        | "remote_minter_outcome_unknown" => {
            "Credential mint outcome is uncertain; follow the required recovery action."
        }
        "oauth_admin_policy_enforced" => {
            "Provider policy prevents credential refresh; review the provider configuration."
        }
        "strategy_descriptor_changed" => "The issuer strategy changed; reconfigure the grant.",
        _ => "Credential refresh failed; follow the required recovery action.",
    }
}

#[cfg(test)]
mod tests;
