// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug)]
struct ParallelDriver {
    inner: Arc<Driver>,
    active: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
    started: Semaphore,
    release: Semaphore,
    block: AtomicBool,
    fail_on: AtomicUsize,
}

struct ActiveRead<'a>(&'a AtomicUsize);
impl Drop for ActiveRead<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tonic::async_trait]
impl CredentialDriver for ParallelDriver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        self.inner.store_credential(request).await
    }

    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _active = ActiveRead(&self.active);
        self.peak.fetch_max(active, Ordering::SeqCst);
        if self.block.load(Ordering::SeqCst) {
            self.started.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        if self.fail_on.load(Ordering::SeqCst) == call {
            return Err(Status::unavailable("private-backend-diagnostic"));
        }
        self.inner.resolve_credentials(requests).await
    }
}

async fn fixture(count: usize) -> (Fixture, Arc<ParallelDriver>, wire::ResolveSecretsRequest) {
    let mut fixture = Fixture::new().await;
    let driver = Arc::new(ParallelDriver {
        inner: fixture.driver.clone(),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
        started: Semaphore::new(0),
        release: Semaphore::new(0),
        block: AtomicBool::new(false),
        fail_on: AtomicUsize::new(0),
    });
    let erased: Arc<dyn CredentialDriver> = driver.clone();
    Arc::get_mut(&mut fixture.service.runtime).unwrap().storage =
        CredentialStorage::new(BTreeMap::from([("db".into(), erased)]), "db".into()).unwrap();
    let runtime = fixture.runtime();
    let mut secrets = Vec::new();
    for index in 0..count {
        let owner = wire::SecretOwner {
            credential_key: format!("OUTPUT_{index}"),
            ..wire_owner()
        };
        let key = format!("put-{index}");
        let created = runtime
            .clone()
            .put(
                test_scope(A),
                wire::PutSecretRequest {
                    owner: Some(owner.clone()),
                    value: format!("value-{index}"),
                    idempotency_key: key.clone(),
                    ..put()
                },
                idempotency(&key).unwrap(),
            )
            .await
            .unwrap();
        secrets.push(wire::ResolveSecretRequest {
            request_id: format!("request-{index}"),
            owner: Some(owner),
            reference: created.reference,
            expected_version: Some(created.version),
        });
    }
    (
        fixture,
        driver,
        wire::ResolveSecretsRequest {
            secrets,
            purpose: wire::ResolvePurpose::SandboxDelivery as i32,
        },
    )
}

async fn started(driver: &ParallelDriver, count: usize) {
    tokio::time::timeout(
        Duration::from_secs(5),
        driver.started.acquire_many(u32::try_from(count).unwrap()),
    )
    .await
    .expect("backend reads must make progress concurrently")
    .unwrap()
    .forget();
}

#[tokio::test]
async fn six_slow_backend_reads_start_together_and_return_one_ordered_snapshot() {
    let (fixture, driver, request) = fixture(6).await;
    driver.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let task = tokio::spawn(async move { runtime.resolve(&test_scope(A), request).await });
    // A sequential resolver cannot start its second read until the first is
    // released. This gate proves concurrency without wall-clock latency tests.
    started(&driver, 6).await;
    driver.release.add_permits(6);
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.secrets.len(), 6);
    for (index, value) in response.secrets.iter().enumerate() {
        assert_eq!(value.request_id, format!("request-{index}"));
        assert_eq!(value.value, format!("value-{index}"));
        assert_eq!(value.version, 1);
    }
    assert_eq!(driver.peak.load(Ordering::SeqCst), 6);
    assert_eq!(driver.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn full_batches_keep_backend_concurrency_bounded() {
    let (fixture, driver, request) = fixture(BATCH_LIMIT).await;
    driver.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let task = tokio::spawn(async move { runtime.resolve(&test_scope(A), request).await });
    started(&driver, 16).await;
    assert_eq!(driver.calls.load(Ordering::SeqCst), 16);
    assert_eq!(driver.active.load(Ordering::SeqCst), 16);
    assert!(driver.started.try_acquire().is_err());
    driver.release.add_permits(BATCH_LIMIT);
    assert_eq!(task.await.unwrap().unwrap().secrets.len(), BATCH_LIMIT);
    assert!(driver.peak.load(Ordering::SeqCst) <= 16);
}

#[tokio::test]
async fn a_failed_parallel_sibling_never_returns_partial_values_or_backend_diagnostics() {
    let (fixture, driver, request) = fixture(6).await;
    driver.fail_on.store(4, Ordering::SeqCst);
    let error = fixture
        .runtime()
        .resolve(&test_scope(A), request)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(!error.message().contains("private-backend-diagnostic"));
    assert_eq!(driver.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rotation_while_parallel_siblings_are_in_flight_fences_the_complete_response() {
    let (fixture, driver, request) = fixture(6).await;
    let rotating = request.secrets.last().unwrap().clone();
    driver.block.store(true, Ordering::SeqCst);
    let runtime = fixture.runtime();
    let reader = runtime.clone();
    let task = tokio::spawn(async move { reader.resolve(&test_scope(A), request).await });
    started(&driver, 6).await;
    runtime
        .clone()
        .put(
            test_scope(A),
            wire::PutSecretRequest {
                owner: rotating.owner,
                reference: rotating.reference,
                expected_version: Some(1),
                value: "rotated-value".into(),
                idempotency_key: "parallel-rotation".into(),
                ..put()
            },
            idempotency("parallel-rotation").unwrap(),
        )
        .await
        .unwrap();
    driver.release.add_permits(6);
    assert_eq!(task.await.unwrap().unwrap_err().code(), Code::Aborted);
    assert_eq!(driver.active.load(Ordering::SeqCst), 0);
}
