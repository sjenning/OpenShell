// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{collections::HashMap, io::Write, sync::Mutex};

#[derive(Debug)]
struct FailingDeletes {
    inner: Arc<Driver>,
    failures: Mutex<HashMap<String, Code>>,
    attempts: Mutex<Vec<String>>,
}
#[tonic::async_trait]
impl CredentialDriver for FailingDeletes {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        self.inner.store_credential(request).await
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        let handle = request.handle.as_ref().unwrap().handle.clone();
        self.attempts.lock().unwrap().push(handle.clone());
        let failure = self.failures.lock().unwrap().get(&handle).copied();
        if let Some(code) = failure {
            return Err(Status::new(code, "private-backend-diagnostic-and-value"));
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
struct CleanupFixture {
    runtime: Arc<Runtime>,
    driver: Arc<FailingDeletes>,
    _fixture: Fixture,
}
impl CleanupFixture {
    async fn new() -> Self {
        let fixture = Fixture::new().await;
        let driver = Arc::new(FailingDeletes {
            inner: fixture.driver.clone(),
            failures: Mutex::new(HashMap::new()),
            attempts: Mutex::new(Vec::new()),
        });
        let erased: Arc<dyn CredentialDriver> = driver.clone();
        let storage = CredentialStorage::new(
            BTreeMap::from([("db".to_string(), erased)]),
            "db".to_string(),
        )
        .unwrap();
        let policy = GatewayPolicy::new(BTreeMap::from([(
            A.to_string(),
            vec!["default".to_string()],
        )]))
        .unwrap();
        let service = CredentialStoreService::new(
            fixture.runtime().repository.clone(),
            storage,
            policy,
            Duration::ZERO,
        )
        .unwrap();
        Self {
            runtime: service.runtime,
            driver,
            _fixture: fixture,
        }
    }
    async fn backing(&self) -> Vec<u8> {
        self.runtime
            .storage
            .stage(
                &test_scope(A),
                &owner(Some(&private_owner())).unwrap(),
                VALUE_PURPOSE,
                "private-secret-value".to_string(),
            )
            .await
            .unwrap()
    }
    fn fail(&self, backing: &[u8], code: Code) -> String {
        let json: serde_json::Value = serde_json::from_slice(backing).unwrap();
        let bytes: Vec<u8> = serde_json::from_value(json["handle"].clone()).unwrap();
        let handle = CredentialHandle::decode(bytes.as_slice()).unwrap().handle;
        self.driver
            .failures
            .lock()
            .unwrap()
            .insert(handle.clone(), code);
        handle
    }
}
fn private_owner() -> wire::SecretOwner {
    wire::SecretOwner {
        provider_id: "private-provider-id".into(),
        credential_key: "PRIVATE_CREDENTIAL_KEY".into(),
        provider: "private-display-name".into(),
        ..wire_owner()
    }
}
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn assert_telemetry(metrics: &str, logs: &Logs, message: &str, handle: &str, count: u64) {
    // CredentialStorage deliberately classifies both backend permission errors
    // and transport failures as Unavailable, without retaining their bodies.
    assert!(metrics.contains(&format!(
        "openshell_issuer_cleanup_deferred_total{{code=\"unavailable\"}} {count}"
    )));
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        logs.matches(message).count(),
        usize::try_from(count).unwrap()
    );
    assert!(logs.contains("Unavailable"));
    for output in [metrics, logs.as_str()] {
        for forbidden in ["private-", "PRIVATE_CREDENTIAL_KEY", handle, A] {
            assert!(
                !output.contains(forbidden),
                "cleanup telemetry leaked metadata"
            );
        }
        for label in ["workspace=", "provider=", "reference=", "backing="] {
            assert!(!output.contains(label));
        }
    }
}

#[tokio::test]
async fn static_cleanup_failures_remain_owned_observable_and_retry_without_blocking_siblings() {
    for code in [Code::PermissionDenied, Code::Unavailable] {
        let fixture = CleanupFixture::new().await;
        let runtime = &fixture.runtime;
        let scope = test_scope(A);
        let supplied = private_owner();
        let owner = owner(Some(&supplied)).unwrap();
        let refs = runtime.repository.references(&scope);
        let failed = fixture.backing().await;
        let sibling = fixture.backing().await;
        for (reference, backing) in [
            ("a-private-reference", &failed),
            ("b-private-reference", &sibling),
        ] {
            refs.registry()
                .adopt(reference, &owner, backing.clone())
                .await
                .unwrap();
            let deleted = runtime
                .clone()
                .delete(
                    scope.clone(),
                    wire::DeleteSecretRequest {
                        owner: Some(supplied.clone()),
                        reference: reference.into(),
                        expected_version: Some(1),
                        idempotency_key: reference.into(),
                    },
                    idempotency(reference).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(deleted.version, 2);
        }
        // Logical revocation completes without requiring backend deletion.
        assert!(fixture.driver.attempts.lock().unwrap().is_empty());
        let handle = fixture.fail(&failed, code);
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let metrics = recorder.handle();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        for count in [1, 2] {
            runtime.maintenance().await.unwrap();
            let failed_state = refs
                .load("a-private-reference")
                .await
                .unwrap()
                .unwrap()
                .state;
            assert!(failed_state.revoked);
            assert_eq!(failed_state.version, 2);
            assert_eq!(failed_state.owner, owner);
            assert_eq!(failed_state.pending_deletions, vec![failed.clone()]);
            let mut request = resolve("a-private-reference", wire::ResolvePurpose::SandboxDelivery);
            request.secrets[0].owner = Some(supplied.clone());
            assert_eq!(
                runtime.resolve(&scope, request).await.unwrap_err().code(),
                Code::NotFound
            );
            let sibling_state = refs
                .load("b-private-reference")
                .await
                .unwrap()
                .unwrap()
                .state;
            assert!(sibling_state.revoked);
            assert!(sibling_state.pending_deletions.is_empty());
            assert!(
                runtime
                    .storage
                    .resolve(&scope, &owner, VALUE_PURPOSE, &failed)
                    .await
                    .is_ok()
            );
            assert_eq!(
                runtime
                    .storage
                    .resolve(&scope, &owner, VALUE_PURPOSE, &sibling)
                    .await
                    .unwrap_err()
                    .code(),
                Code::NotFound
            );
            assert_telemetry(
                &metrics.render(),
                &logs,
                "issuer reference cleanup deferred",
                &handle,
                count,
            );
        }
        fixture.driver.failures.lock().unwrap().clear();
        runtime.maintenance().await.unwrap();
        let state = refs
            .load("a-private-reference")
            .await
            .unwrap()
            .unwrap()
            .state;
        assert!(state.revoked);
        assert_eq!(state.version, 2);
        assert!(state.pending_deletions.is_empty());
        assert_eq!(
            runtime
                .storage
                .resolve(&scope, &owner, VALUE_PURPOSE, &failed)
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(fixture.driver.attempts.lock().unwrap().len(), 4);
        assert_telemetry(
            &metrics.render(),
            &logs,
            "issuer reference cleanup deferred",
            &handle,
            2,
        );
    }
}

#[tokio::test]
async fn abandoned_candidates_keep_cleanup_ownership_and_retry_without_blocking_siblings() {
    for code in [Code::PermissionDenied, Code::Unavailable] {
        let fixture = CleanupFixture::new().await;
        let runtime = &fixture.runtime;
        let scope = test_scope(A);
        let owner = owner(Some(&private_owner())).unwrap();
        let store = runtime.repository.for_gateway(&scope);
        let failed = fixture.backing().await;
        let sibling = fixture.backing().await;
        for (key, backing) in [
            ("a-private-candidate", &failed),
            ("b-private-candidate", &sibling),
        ] {
            store
                .commit(
                    &[Mutation::Put {
                        kind: CANDIDATE_KIND.into(),
                        key: key.into(),
                        expected: None,
                        payload: encode(&Candidate {
                            operation_key: format!("private-operation:{key}"),
                            owner: owner.clone(),
                            purpose: VALUE_PURPOSE.into(),
                            backing: backing.clone(),
                        })
                        .unwrap(),
                    }],
                    &[],
                )
                .await
                .unwrap();
        }
        let handle = fixture.fail(&failed, code);
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let metrics = recorder.handle();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        for count in [1, 2] {
            runtime.maintenance().await.unwrap();
            let record = store
                .load(CANDIDATE_KIND, "a-private-candidate")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(record.revision, count + 1);
            let retained: Candidate = decode(&record.payload).unwrap();
            assert_eq!(retained.owner, owner);
            assert_eq!(retained.backing, failed);
            assert_eq!(retained.purpose, VALUE_PURPOSE);
            assert_eq!(
                retained.operation_key,
                "private-operation:a-private-candidate"
            );
            assert!(
                store
                    .load(CANDIDATE_KIND, "b-private-candidate")
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                runtime
                    .storage
                    .resolve(&scope, &owner, VALUE_PURPOSE, &failed)
                    .await
                    .is_ok()
            );
            assert_eq!(
                runtime
                    .storage
                    .resolve(&scope, &owner, VALUE_PURPOSE, &sibling)
                    .await
                    .unwrap_err()
                    .code(),
                Code::NotFound
            );
            assert_telemetry(
                &metrics.render(),
                &logs,
                "issuer candidate cleanup deferred",
                &handle,
                count,
            );
        }
        fixture.driver.failures.lock().unwrap().clear();
        runtime.maintenance().await.unwrap();
        assert!(
            store
                .list(CANDIDATE_KIND, None, 128)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            runtime
                .storage
                .resolve(&scope, &owner, VALUE_PURPOSE, &failed)
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
        assert_eq!(fixture.driver.attempts.lock().unwrap().len(), 4);
        assert_telemetry(
            &metrics.render(),
            &logs,
            "issuer candidate cleanup deferred",
            &handle,
            2,
        );
    }
}
