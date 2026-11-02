// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::{RecoveryAction, RetrySchedule, StrategyDescriptor, TokenMinter};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::Code;

type Trace = Arc<Mutex<Vec<&'static str>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Success,
    Current,
    LeaseFailure,
    PrepareFailure,
    ResolveFailure,
    MintFailure,
    CommitFailure,
    RecordFailure,
    MismatchedAttempt,
    MissingAttempt,
}

struct MemoryStore {
    trace: Trace,
    mode: Mode,
    attempt_ids: Mutex<Vec<String>>,
}
struct Lease(Trace);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("release");
    }
}

fn failure() -> MintFailure {
    MintFailure {
        status: Status::failed_precondition("uncertain exchange"),
        recovery_action: RecoveryAction::Reauthorize,
        failure_code: "uncertain",
        provider_error_subtype: None,
        retry_schedule: RetrySchedule::Parked,
    }
}

#[async_trait]
impl RefreshStateStore for MemoryStore {
    type Snapshot = u64;
    type Attempt = (u64, String);
    type Lease = Lease;
    fn coordination_key(&self, _: &u64) -> String {
        "immutable-grant".to_string()
    }
    async fn acquire_lease(&self, _: &u64) -> Result<Lease, Status> {
        self.trace.lock().unwrap().push("lease");
        if self.mode == Mode::LeaseFailure {
            return Err(Status::unavailable("lease unavailable"));
        }
        Ok(Lease(self.trace.clone()))
    }
    async fn prepare(
        &self,
        observed: u64,
        trigger: RefreshTrigger,
        attempt_id: &str,
    ) -> Result<Preparation<u64, Self::Attempt>, Status> {
        assert_eq!(trigger, RefreshTrigger::Automatic);
        assert_eq!(
            uuid::Uuid::parse_str(attempt_id).unwrap().get_version_num(),
            4
        );
        self.attempt_ids
            .lock()
            .unwrap()
            .push(attempt_id.to_string());
        self.trace.lock().unwrap().push("prepare");
        match self.mode {
            Mode::Current => Ok(Preparation::Current(observed + 1)),
            Mode::PrepareFailure => Err(Status::aborted("fenced before minting")),
            _ => Ok(Preparation::Ready((observed, attempt_id.to_string()))),
        }
    }
    async fn mint_request(&self, attempt: &Self::Attempt) -> Result<MintRequest, MintFailure> {
        self.trace.lock().unwrap().push("resolve");
        if self.mode == Mode::ResolveFailure {
            return Err(failure());
        }
        Ok(MintRequest {
            strategy: "custom:example".to_string(),
            attempt_id: match self.mode {
                Mode::MismatchedAttempt => "stale-attempt".to_string(),
                Mode::MissingAttempt => String::new(),
                _ => attempt.1.clone(),
            },
            config: HashMap::new(),
            secret_material: HashMap::new(),
        })
    }
    async fn commit(&self, attempt: Self::Attempt, response: MintResponse) -> Result<u64, Status> {
        self.trace.lock().unwrap().push("commit");
        assert_eq!(response.outputs["access_token"], "value");
        if self.mode == Mode::CommitFailure {
            return Err(Status::aborted("publication fenced"));
        }
        Ok(attempt.0 + 1)
    }
    async fn record_failure(&self, _: &Self::Attempt, failure: MintFailure) -> Result<(), Status> {
        self.trace.lock().unwrap().push("failure");
        if matches!(self.mode, Mode::MismatchedAttempt | Mode::MissingAttempt) {
            assert_eq!(failure.recovery_action, RecoveryAction::Investigate);
            assert_eq!(failure.failure_code, "refresh_attempt_mismatch");
        } else {
            assert_eq!(failure.recovery_action, RecoveryAction::Reauthorize);
        }
        assert_eq!(failure.retry_schedule, RetrySchedule::Parked);
        if self.mode == Mode::RecordFailure {
            return Err(Status::aborted("failure receipt fenced"));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Minter {
    trace: Trace,
    mode: Mode,
}
#[async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:example".to_string(),
            config: Vec::new(),
            secret_material: Vec::new(),
            outputs: vec!["access_token".to_string()],
            rotated_secret_material: Vec::new(),
        }
    }
    async fn mint(&self, request: MintRequest) -> Result<MintResponse, MintFailure> {
        self.trace.lock().unwrap().push("mint");
        assert_eq!(
            uuid::Uuid::parse_str(&request.attempt_id)
                .unwrap()
                .get_version_num(),
            4
        );
        if matches!(self.mode, Mode::MintFailure | Mode::RecordFailure) {
            return Err(failure());
        }
        Ok(MintResponse {
            outputs: HashMap::from([("access_token".to_string(), "value".to_string())]),
            expiration_time_ms: i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis(),
            )
            .unwrap()
                + 60_000,
            rotated_secret_material: HashMap::new(),
        })
    }
}
struct Sink(Trace);
#[async_trait]
impl RefreshSink<u64> for Sink {
    async fn committed(&self, snapshot: &u64) {
        assert_eq!(*snapshot, 2);
        self.0.lock().unwrap().push("notify");
    }
}

fn engine(mode: Mode) -> (RefreshEngine<MemoryStore>, Trace) {
    let trace: Trace = Arc::default();
    let mut registry = MinterRegistry::default();
    registry
        .register_custom(Arc::new(Minter {
            trace: trace.clone(),
            mode,
        }))
        .unwrap();
    (
        RefreshEngine::new(
            Arc::new(MemoryStore {
                trace: trace.clone(),
                mode,
                attempt_ids: Mutex::default(),
            }),
            Arc::new(registry),
            Arc::new(Sink(trace.clone())),
            RefreshCoordinator::default(),
        ),
        trace,
    )
}

#[tokio::test]
async fn engine_notifies_only_after_durable_publication_and_holds_the_lease() {
    let (engine, trace) = engine(Mode::Success);
    assert_eq!(
        engine.refresh(1, RefreshTrigger::Automatic).await.unwrap(),
        2
    );
    assert_eq!(
        *trace.lock().unwrap(),
        [
            "lease", "prepare", "resolve", "mint", "commit", "notify", "release"
        ]
    );
}

#[tokio::test]
async fn coalesced_refresh_does_not_resolve_mint_commit_or_notify() {
    let (engine, trace) = engine(Mode::Current);
    assert_eq!(
        engine.refresh(1, RefreshTrigger::Automatic).await.unwrap(),
        2
    );
    assert_eq!(*trace.lock().unwrap(), ["lease", "prepare", "release"]);
}

#[tokio::test]
async fn fencing_and_lease_failures_never_reach_the_minter() {
    for (mode, expected) in [
        (Mode::LeaseFailure, vec!["lease"]),
        (Mode::PrepareFailure, vec!["lease", "prepare", "release"]),
    ] {
        let (engine, trace) = engine(mode);
        assert!(engine.refresh(1, RefreshTrigger::Automatic).await.is_err());
        assert_eq!(*trace.lock().unwrap(), expected);
    }
}

#[tokio::test]
async fn resolution_and_mint_errors_are_recorded_without_publication() {
    for mode in [Mode::ResolveFailure, Mode::MintFailure] {
        let (engine, trace) = engine(mode);
        assert_eq!(
            engine
                .refresh(1, RefreshTrigger::Automatic)
                .await
                .unwrap_err()
                .code(),
            Code::FailedPrecondition
        );
        let trace = trace.lock().unwrap();
        assert!(trace.contains(&"failure"));
        assert!(!trace.contains(&"commit"));
        assert!(!trace.contains(&"notify"));
        assert_eq!(trace.last(), Some(&"release"));
    }
}

#[tokio::test]
async fn partial_publication_recovery_is_not_overwritten_by_generic_mint_failure() {
    let (engine, trace) = engine(Mode::CommitFailure);
    assert_eq!(
        engine
            .refresh(1, RefreshTrigger::Automatic)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        *trace.lock().unwrap(),
        ["lease", "prepare", "resolve", "mint", "commit", "release"]
    );
}

#[tokio::test]
async fn failure_receipt_fencing_is_reported_instead_of_the_upstream_error() {
    let (engine, trace) = engine(Mode::RecordFailure);
    assert_eq!(
        engine
            .refresh(1, RefreshTrigger::Automatic)
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        *trace.lock().unwrap(),
        ["lease", "prepare", "resolve", "mint", "failure", "release"]
    );
}

#[tokio::test]
async fn missing_or_stale_attempt_ids_are_parked_before_contacting_the_minter() {
    for mode in [Mode::MismatchedAttempt, Mode::MissingAttempt] {
        let (engine, trace) = engine(mode);
        let error = engine
            .refresh(1, RefreshTrigger::Automatic)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert!(!error.message().contains("stale-attempt"));
        assert_eq!(
            *trace.lock().unwrap(),
            ["lease", "prepare", "resolve", "failure", "release"]
        );
    }
}

#[tokio::test]
async fn successive_attempts_get_distinct_issuer_owned_ids() {
    let (engine, _) = engine(Mode::MintFailure);
    for _ in 0..2 {
        assert!(engine.refresh(1, RefreshTrigger::Automatic).await.is_err());
    }
    let ids = engine.store.attempt_ids.lock().unwrap();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}
