// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Identify failures at the credential metadata boundary, not by a store
//! error's gRPC code. Only these failures invalidate an installed environment.

use std::collections::HashMap;

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
pub struct Source<'a>(&'a dyn ProviderCredentialSource);

impl Source<'_> {
    pub(crate) fn selected(state: &crate::ServerState) -> Option<Source<'_>> {
        state.provider_source.as_deref().map(Source)
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
        self.0.project_expiration_metadata(store, provider).await
    }

    async fn reference_versions(
        &self,
        store: &Store,
        provider: &Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        self.0.reference_versions(store, provider).await
    }

    async fn capture_metadata(
        &self,
        store: &Store,
        provider: &mut Provider,
    ) -> Result<HashMap<String, u64>, Status> {
        self.0
            .capture_metadata(store, provider)
            .await
            .map_err(classify)
    }

    async fn resolve_provider_handles_for(
        &self,
        provider: &Provider,
        now_ms: i64,
        purpose: CredentialReadPurpose,
    ) -> Result<ResolvedProviderCredentials, Status> {
        self.0
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
}
