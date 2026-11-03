// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Identify failures at the credential metadata boundary, not by a store
//! error's gRPC code. Only these failures invalidate an installed environment.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use openshell_core::proto::Provider;
use tonic::{Code, Status};

use crate::credential_source::{CredentialReadPurpose, ProviderCredentialSource};
use crate::credentials::ResolvedProviderCredentials;
use crate::persistence::Store;

const MARKER: &str = "openshell-credential-metadata-unavailable";

/// A build-local adapter for explicitly selected credential sources. Provider
/// records and refresh states still load from the store normally; only an
/// external metadata capture's unavailable/missing/racing result receives this
/// private marker. The default embedded runtime remains unwrapped: its metadata
/// reads use the gateway database, whose outages must retain normal retry
/// behavior. Invalid handles/owners keep their original validation errors.
#[derive(Debug)]
pub struct Source<'a> {
    inner: &'a dyn ProviderCredentialSource,
    defer_unavailable: bool,
    unavailable: Mutex<Option<Box<Status>>>,
}

impl Source<'_> {
    pub(crate) fn selected(state: &crate::ServerState) -> Option<Source<'_>> {
        state.provider_source.as_deref().map(|source| Source {
            inner: source,
            defer_unavailable: false,
            unavailable: Mutex::new(None),
        })
    }

    /// Polling and bootstrap must deliver policy/settings even when external
    /// metadata is unavailable, so the supervisor can revoke installed static
    /// credentials. Keep the error beside those inputs; never resolve values
    /// from incomplete metadata or substitute the embedded source.
    pub(crate) fn for_delivery(state: &crate::ServerState) -> Option<Source<'_>> {
        Self::selected(state).map(|mut source| {
            source.defer_unavailable = true;
            source
        })
    }

    pub(crate) fn take_unavailable(&self) -> Option<Box<Status>> {
        self.unavailable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

pub(super) fn is_unavailable(error: &Status) -> bool {
    error.metadata().get(MARKER).is_some()
}

fn classify(mut error: Status) -> Status {
    if matches!(
        error.code(),
        Code::Unavailable | Code::NotFound | Code::Aborted
    ) {
        error
            .metadata_mut()
            .insert(MARKER, "true".parse().expect("static metadata"));
    }
    error
}

#[async_trait]
impl ProviderCredentialSource for Source<'_> {
    async fn project_expiration_metadata(
        &self,
        store: &Store,
        provider: &mut Provider,
    ) -> Result<(), Status> {
        self.inner
            .project_expiration_metadata(store, provider)
            .await
    }

    async fn reference_versions(
        &self,
        store: &Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        self.inner.reference_versions(store, provider).await
    }

    async fn capture_metadata(
        &self,
        store: &Store,
        provider: &mut Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        let original = self.defer_unavailable.then(|| provider.clone());
        match self.inner.capture_metadata(store, provider).await {
            Ok(versions) => Ok(versions),
            Err(error) => {
                let error = classify(error);
                if self.defer_unavailable && is_unavailable(&error) {
                    *provider = original.expect("delivery capture saved the authored provider");
                    self.unavailable
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get_or_insert_with(|| Box::new(error));
                    // No version is guessed. The input-level error forbids
                    // value resolution and marks the delivery identity failed.
                    Ok(HashMap::new())
                } else {
                    Err(error)
                }
            }
        }
    }

    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        purpose: CredentialReadPurpose,
    ) -> Result<ResolvedProviderCredentials, Status> {
        self.inner
            .resolve_provider_handles_for(provider, now_ms, purpose)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn embedded_reference_database_failure_is_not_external_metadata_unavailability() {
        use openshell_core::proto::{CredentialHandle, ObjectMeta};
        let state = crate::grpc::test_support::test_server_state().await;
        let selected = Source::selected(&state);
        assert!(
            selected.is_none(),
            "the default embedded runtime must not be classified as an external source"
        );
        assert!(Source::for_delivery(&state).is_none());
        let source: &dyn ProviderCredentialSource = match selected.as_ref() {
            Some(source) => source,
            None => state.provider_credential_source(),
        };
        let mut provider = Provider {
            metadata: Some(ObjectMeta {
                id: "provider-id".into(),
                name: "provider".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            credential_handles: HashMap::from([(
                "TOKEN".into(),
                CredentialHandle {
                    driver: "test-static".into(),
                    handle: "opaque".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        // The provider and configuration may already be loaded when this
        // separate credential-reference row read loses its database connection.
        state.store.close().await;
        let error = source
            .capture_metadata(&state.store, &mut provider)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert!(!is_unavailable(&error));
    }

    #[test]
    fn only_credential_metadata_availability_errors_are_classified() {
        for code in [Code::Unavailable, Code::NotFound, Code::Aborted] {
            assert!(!is_unavailable(&Status::new(code, "store failure")));
            let error = classify(Status::new(code, "metadata failure"));
            assert!(is_unavailable(&error));
            assert_eq!(error.code(), code);
        }
        for code in [
            Code::Internal,
            Code::FailedPrecondition,
            Code::InvalidArgument,
            Code::PermissionDenied,
        ] {
            assert!(!is_unavailable(&classify(Status::new(
                code,
                "invalid metadata"
            ))));
        }
    }

    #[derive(Debug)]
    struct CaptureFailure(Code);

    #[async_trait]
    impl ProviderCredentialSource for CaptureFailure {
        async fn project_expiration_metadata(
            &self,
            _store: &Store,
            _provider: &mut Provider,
        ) -> Result<(), Status> {
            unreachable!("capture is implemented atomically")
        }

        async fn reference_versions(
            &self,
            _store: &Store,
            _provider: &Provider,
        ) -> Result<HashMap<String, u64>, Status> {
            unreachable!("capture is implemented atomically")
        }

        async fn capture_metadata(
            &self,
            _store: &Store,
            provider: &mut Provider,
        ) -> Result<HashMap<String, u64>, Status> {
            provider.credential_expiration_times.insert(
                "partial-projection".into(),
                prost_types::Timestamp {
                    seconds: 42,
                    nanos: 7,
                },
            );
            Err(Status::new(self.0, "metadata capture failed"))
        }

        async fn resolve_provider_handles_for(
            &self,
            _provider: &Provider,
            _now_ms: i64,
            _purpose: CredentialReadPurpose,
        ) -> Result<ResolvedProviderCredentials, Status> {
            unreachable!("metadata capture must not resolve credential values")
        }
    }

    #[tokio::test]
    async fn delivery_defers_only_availability_and_discards_partial_metadata_projection() {
        let state = crate::grpc::test_support::test_server_state().await;
        for code in [Code::Unavailable, Code::NotFound, Code::Aborted] {
            let failure = CaptureFailure(code);
            let source = Source {
                inner: &failure,
                defer_unavailable: true,
                unavailable: Mutex::new(None),
            };
            let original = Provider::default();
            let mut provider = original.clone();
            assert!(
                source
                    .capture_metadata(&state.store, &mut provider)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                provider, original,
                "a failed projection is never authoritative"
            );
            let error = source
                .take_unavailable()
                .expect("failed inputs carry the original error");
            assert_eq!(error.code(), code);
            assert!(is_unavailable(&error));
        }
        for code in [
            Code::Internal,
            Code::FailedPrecondition,
            Code::InvalidArgument,
            Code::PermissionDenied,
        ] {
            let failure = CaptureFailure(code);
            let source = Source {
                inner: &failure,
                defer_unavailable: true,
                unavailable: Mutex::new(None),
            };
            assert_eq!(
                source
                    .capture_metadata(&state.store, &mut Provider::default())
                    .await
                    .unwrap_err()
                    .code(),
                code
            );
            assert!(
                source.take_unavailable().is_none(),
                "invalid ownership/handles cannot become deliverable inputs"
            );
        }
    }
}
