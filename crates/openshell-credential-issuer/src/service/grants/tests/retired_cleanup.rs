// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{ReferenceStateStore, repository::grants::GrantAttempt};
use tonic::Code;

#[derive(Debug, Default)]
struct DeleteControl {
    fail: AtomicBool,
    attempts: AtomicUsize,
}

#[derive(Debug)]
struct DeleteFailingDriver {
    inner: Driver,
    control: Arc<DeleteControl>,
}

#[tonic::async_trait]
impl CredentialDriver for DeleteFailingDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        self.inner.store_credential(request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.control.attempts.fetch_add(1, Ordering::SeqCst);
        if self.control.fail.load(Ordering::SeqCst) {
            return Err(Status::permission_denied("private-delete-only-error"));
        }
        self.inner.delete_credential(request).await
    }

    async fn resolve_credentials(
        &self,
        request: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.inner.resolve_credentials(request).await
    }
}

async fn fixture() -> (Fixture, Arc<DeleteControl>) {
    let directory = tempfile::tempdir().unwrap();
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let config = toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.path().join("key").to_str().unwrap().into()),
    )]);
    let fail = Arc::new(AtomicBool::new(false));
    let resolves = Arc::new(AtomicUsize::new(0));
    let fail_resolves = Arc::new(AtomicBool::new(false));
    let control = Arc::new(DeleteControl::default());
    let driver: Arc<dyn CredentialDriver> = Arc::new(DeleteFailingDriver {
        inner: Driver {
            inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
            fail: fail.clone(),
            resolves: resolves.clone(),
            fail_resolves: fail_resolves.clone(),
        },
        control: control.clone(),
    });
    let storage =
        CredentialStorage::new(BTreeMap::from([("db".into(), driver)]), "db".into()).unwrap();
    let policy = GatewayPolicy::new(BTreeMap::from([(A.into(), vec!["default".into()])])).unwrap();
    let store =
        CredentialStoreService::new(repository, storage, policy, Duration::from_secs(2)).unwrap();
    let minter = Arc::new(Minter {
        backend: fail,
        ..Minter::default()
    });
    let mut registry = MinterRegistry::default();
    registry.register_custom(minter.clone()).unwrap();
    let service = CredentialRefreshService::new(
        &store,
        Arc::new(registry),
        MintResultSpool::new(EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap()),
    )
    .unwrap();
    (
        Fixture {
            service,
            store,
            minter,
            resolves,
            fail_resolves,
            _directory: directory,
        },
        control,
    )
}

async fn published(fixture: &Fixture) -> wire::CreateGrantResponse {
    let grant = create(fixture).await;
    fixture
        .runtime()
        .ensure(test_scope(A), grant.grant.clone(), 0)
        .await
        .unwrap();
    grant
}

async fn schedule_now(fixture: &Fixture, id: &str) {
    let runtime = fixture.runtime();
    let scope = test_scope(A);
    let loaded = runtime.load(&scope, id).await.unwrap();
    let mut state = loaded.state;
    state.next_refresh_at_ms = now_ms().unwrap() - 1;
    state.version += 1;
    runtime
        .save(&scope, loaded.revision, &state, Vec::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn retired_delete_failure_does_not_block_scheduled_refresh_and_cleanup_retries() {
    let (fixture, deletes) = fixture().await;
    let grant = published(&fixture).await;
    let runtime = fixture.runtime();
    let scope = test_scope(A);
    let before = runtime.load(&scope, &grant.grant).await.unwrap();
    assert_eq!(before.state.retired.len(), 1);
    let retired = before.state.retired[0].clone();
    deletes.fail.store(true, Ordering::SeqCst);
    schedule_now(&fixture, &grant.grant).await;

    runtime.tick().await.unwrap();

    let refreshed = runtime.load(&scope, &grant.grant).await.unwrap();
    assert_eq!(refreshed.state.phase, GrantPhase::Refreshed);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        *fixture.minter.seen.lock().unwrap(),
        vec!["initial-refresh", "rotated-1"]
    );
    let outputs = values(&fixture, &grant).await;
    assert!(outputs.secrets.iter().all(|secret| secret.version == 3));
    assert_eq!(outputs.secrets[0].value, "first-2");
    assert_eq!(outputs.secrets[1].value, "second-2");
    assert_eq!(refreshed.state.retired.len(), 2);
    assert!(
        refreshed
            .state
            .retired
            .iter()
            .any(|entry| entry.backing == retired.backing)
    );
    assert!(deletes.attempts.load(Ordering::SeqCst) > 0);
    assert_eq!(
        runtime
            .store
            .storage
            .resolve(&scope, &retired.owner, &retired.purpose, &retired.backing)
            .await
            .unwrap()
            .value,
        "initial-refresh"
    );
    let refs = runtime.store.repository.references(&scope);
    for binding in refreshed.state.definition.outputs.values() {
        assert!(
            !refs
                .load(&binding.reference)
                .await
                .unwrap()
                .unwrap()
                .state
                .pending_deletions
                .is_empty()
        );
    }

    deletes.fail.store(false, Ordering::SeqCst);
    runtime.tick().await.unwrap();
    let cleaned = runtime.load(&scope, &grant.grant).await.unwrap();
    assert!(cleaned.state.retired.is_empty());
    assert_eq!(
        runtime
            .store
            .storage
            .resolve(&scope, &retired.owner, &retired.purpose, &retired.backing)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    for binding in cleaned.state.definition.outputs.values() {
        assert!(
            refs.load(&binding.reference)
                .await
                .unwrap()
                .unwrap()
                .state
                .pending_deletions
                .is_empty()
        );
    }
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(values(&fixture, &grant).await, outputs);
}

#[tokio::test]
async fn retired_delete_failure_does_not_block_durable_known_result_recovery() {
    let (fixture, deletes) = fixture().await;
    let grant = published(&fixture).await;
    deletes.fail.store(true, Ordering::SeqCst);
    fixture.minter.fail_backend.store(true, Ordering::SeqCst);
    let error = fixture
        .runtime()
        .rotate(
            test_scope(A),
            grant.grant.clone(),
            idempotency("interrupted-publication").unwrap(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    let pending = fixture
        .runtime()
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    assert_eq!(pending.state.phase, GrantPhase::Publishing);
    assert!(pending.state.attempt.unwrap().encrypted_result.is_some());
    assert_eq!(pending.state.retired.len(), 1);
    fixture.minter.backend.store(false, Ordering::SeqCst);
    let restarted = CredentialRefreshService::new(
        &fixture.store,
        fixture.runtime().minters.clone(),
        fixture.runtime().spool.clone(),
    )
    .unwrap();

    restarted.runtime.tick().await.unwrap();

    let recovered = restarted
        .runtime
        .load(&test_scope(A), &grant.grant)
        .await
        .unwrap();
    assert_eq!(recovered.state.phase, GrantPhase::Refreshed);
    assert!(recovered.state.attempt.is_none());
    assert_eq!(recovered.state.retired.len(), 2);
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
    assert_eq!(values(&fixture, &grant).await.secrets[0].value, "first-2");
    let replay = restarted
        .runtime
        .rotate(
            test_scope(A),
            grant.grant.clone(),
            idempotency("interrupted-publication").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status.unwrap().state, "refreshed");
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);

    deletes.fail.store(false, Ordering::SeqCst);
    restarted.runtime.tick().await.unwrap();
    assert!(
        restarted
            .runtime
            .load(&test_scope(A), &grant.grant)
            .await
            .unwrap()
            .state
            .retired
            .is_empty()
    );
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retired_delete_failure_still_parks_an_interrupted_unknown_exchange() {
    let (fixture, deletes) = fixture().await;
    let grant = published(&fixture).await;
    let runtime = fixture.runtime();
    let scope = test_scope(A);
    let loaded = runtime.load(&scope, &grant.grant).await.unwrap();
    let mut state = loaded.state;
    // Model a process restart after admission, without a durable mint result.
    state.phase = GrantPhase::Refreshing;
    state.version += 1;
    state.next_refresh_at_ms = now_ms().unwrap() - 1;
    state.attempt = Some(GrantAttempt {
        id: "interrupted-unknown-attempt".into(),
        encrypted_result: None,
        expected_output_versions: BTreeMap::from([("first".into(), 2), ("second".into(), 2)]),
        output_candidates: BTreeMap::new(),
        material_candidates: BTreeMap::new(),
        rotation_receipt: None,
    });
    runtime
        .save(&scope, loaded.revision, &state, Vec::new())
        .await
        .unwrap();
    deletes.fail.store(true, Ordering::SeqCst);

    runtime.tick().await.unwrap();
    runtime.tick().await.unwrap();

    let parked = runtime.load(&scope, &grant.grant).await.unwrap();
    assert_eq!(parked.state.phase, GrantPhase::Parked);
    assert_eq!(parked.state.failure_code, "mint_outcome_unknown");
    assert_eq!(
        parked.state.recovery_action,
        Some(RecoveryAction::Investigate)
    );
    assert_eq!(parked.state.next_refresh_at_ms, i64::MAX);
    assert_eq!(parked.state.retired.len(), 1);
    assert!(parked.state.attempt.unwrap().encrypted_result.is_none());
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);

    deletes.fail.store(false, Ordering::SeqCst);
    runtime.tick().await.unwrap();
    let cleaned = runtime.load(&scope, &grant.grant).await.unwrap();
    assert_eq!(cleaned.state.phase, GrantPhase::Parked);
    assert!(cleaned.state.retired.is_empty());
    assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retired_delete_failure_never_restarts_deleted_or_detached_grants() {
    for detached in [false, true] {
        let (fixture, deletes) = fixture().await;
        let grant = published(&fixture).await;
        let runtime = fixture.runtime();
        let scope = test_scope(A);
        let outputs = values(&fixture, &grant).await;
        deletes.fail.store(true, Ordering::SeqCst);
        if detached {
            runtime
                .clone()
                .detach(
                    scope.clone(),
                    grant.grant.clone(),
                    idempotency("detach").unwrap(),
                )
                .await
                .unwrap();
        } else {
            runtime
                .clone()
                .delete(
                    scope.clone(),
                    grant.grant.clone(),
                    idempotency("delete").unwrap(),
                )
                .await
                .unwrap();
        }

        runtime.tick().await.unwrap();

        let stopped = runtime.load(&scope, &grant.grant).await.unwrap();
        assert_eq!(
            stopped.state.phase,
            if detached {
                GrantPhase::Detached
            } else {
                GrantPhase::Deleting
            }
        );
        assert!(!stopped.state.retired.is_empty());
        assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
        if detached {
            assert_eq!(values(&fixture, &grant).await, outputs);
        } else {
            for binding in stopped.state.definition.outputs.values() {
                let reference = runtime
                    .store
                    .repository
                    .references(&scope)
                    .load(&binding.reference)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(reference.state.revoked);
                assert!(!reference.state.pending_deletions.is_empty());
            }
        }

        deletes.fail.store(false, Ordering::SeqCst);
        runtime.tick().await.unwrap();
        let cleaned = runtime.load(&scope, &grant.grant).await.unwrap();
        assert_eq!(
            cleaned.state.phase,
            if detached {
                GrantPhase::Detached
            } else {
                GrantPhase::Deleted
            }
        );
        assert!(cleaned.state.retired.is_empty());
        assert_eq!(fixture.minter.calls.load(Ordering::SeqCst), 1);
        if detached {
            assert_eq!(values(&fixture, &grant).await, outputs);
        }
    }
}
