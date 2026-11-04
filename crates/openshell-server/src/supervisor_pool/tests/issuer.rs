// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Real supervisor publication/load/reconcile and paused-publication recovery.
use super::super::{LAUNCH_MATERIAL_KEY, MATERIAL_CANDIDATE_OBJECT_TYPE, RecordPhase};
use super::{Fixture, assignment};
use crate::{
    auth::sandbox_jwt::SandboxSessionJwtAuthority,
    credential_source::{RemoteProviderSource, tests::issuer::Issuer},
    credentials::CredentialRuntime,
    persistence::ObjectListQuery,
};
use openshell_core::{
    Config,
    proto::{CredentialHandle, SandboxPhase, credentials::store::v1 as wire},
};
use prost::Message as _;
use std::{sync::Arc, time::Duration};
use tonic::Code;

const INTENT: &str = "credential_issuer_internal_intent_v1";
struct IssuerFixture {
    fixture: Fixture,
    issuer: Issuer,
    source: RemoteProviderSource,
}
impl IssuerFixture {
    async fn new() -> Self {
        let issuer = Issuer::start().await;
        let store = Arc::new(crate::persistence::test_store().await);
        let source = RemoteProviderSource::new("primary", issuer.watched.clone())
            .unwrap()
            .with_gateway_store(store.clone());
        let credentials =
            CredentialRuntime::from_issuer(&Config::new(None), source.clone()).unwrap();
        assert!(credentials.issuer_drivers().0.is_empty());
        assert!(
            credentials
                .internal_secrets()
                .stored_credential_count()
                .is_none()
        );
        let key = openshell_bootstrap::jwt::generate_jwt_key().unwrap();
        let authority = Arc::new(
            SandboxSessionJwtAuthority::from_pem(
                key.signing_key_pem.as_bytes(),
                key.public_key_pem.as_bytes(),
                key.kid,
                "test-gateway",
                Some(Duration::from_mins(15)),
            )
            .unwrap(),
        );
        let fixture = Fixture {
            store,
            authority,
            credentials,
        };
        issuer
            .watched
            .wait_synchronized(Duration::from_secs(5))
            .await
            .unwrap();
        Self {
            fixture,
            issuer,
            source,
        }
    }
    async fn metadata(
        &self,
        route: &str,
        reference: &str,
    ) -> Result<wire::ResolveSecretsResponse, tonic::Status> {
        self.issuer
            .raw
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: vec![wire::ResolveSecretRequest {
                    owner: Some(typed_owner(route)),
                    reference: reference.into(),
                    request_id: "material".into(),
                    expected_version: None,
                }],
            })
            .await
    }
    async fn intent(&self, route: &str, phase: &str) {
        let rows = self
            .fixture
            .store
            .list_object_page(INTENT, ObjectListQuery::AllWorkspaces, None, 128)
            .await
            .unwrap()
            .records;
        assert_eq!(rows.len(), 1);
        let state: serde_json::Value = serde_json::from_slice(&rows[0].payload).unwrap();
        assert_eq!(state["phase"], phase);
        assert_eq!(state["owner"]["kind"], "supervisor_instance");
        assert_eq!(state["owner"]["provider_id"], route);
        assert!(!String::from_utf8_lossy(&rows[0].payload).contains("\"launch\""));
    }
}
fn reference_from_handle(bytes: &[u8]) -> String {
    let handle = CredentialHandle::decode(bytes).unwrap();
    let binding: serde_json::Value = serde_json::from_str(&handle.handle).unwrap();
    binding["reference"].as_str().unwrap().to_string()
}
fn typed_owner(route: &str) -> wire::SecretOwner {
    wire::SecretOwner {
        workspace: "default".into(),
        credential_key: LAUNCH_MATERIAL_KEY.into(),
        kind: Some(wire::secret_owner::Kind::SupervisorInstance(
            wire::SupervisorInstanceSecretOwner {
                instance_id: route.into(),
            },
        )),
        ..Default::default()
    }
}

#[tokio::test]
async fn selected_issuer_records_loads_and_reconciles_supervisor_material_without_local_drivers() {
    let fixture = IssuerFixture::new().await;
    fixture.fixture.member("m1", "p1", false).await;
    fixture
        .fixture
        .sandbox("issuer-sandbox", "generation-1", SandboxPhase::Ready)
        .await;
    let pool = fixture.fixture.replica("issuer-writer");
    let instance = assignment("rt-issuer-route", "issuer-sandbox", "generation-1");
    let record = pool.record_assignment(&instance).await.unwrap();
    assert_eq!(record.payload.phase, RecordPhase::Published);
    let reference = reference_from_handle(&record.payload.material_handle);
    fixture.intent(&instance.route, "published").await;
    let status = fixture.metadata(&instance.route, &reference).await.unwrap();
    assert!(status.secrets[0].value.is_empty());
    assert!(!status.secrets[0].pending_value);
    fixture
        .issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    let other = fixture.fixture.replica("issuer-reader");
    assert_eq!(
        other.load_material(&record.payload).await.unwrap(),
        instance.launch_material
    );
    let repeated = other.record_assignment(&instance).await.unwrap();
    assert_eq!(
        repeated.payload.material_handle,
        record.payload.material_handle
    );
    fixture
        .fixture
        .own(&instance.route, &instance.sandbox_id, "m1", "p1")
        .await;
    other.reconcile_once().await.unwrap();
    let view = other.controller.pool_view().unwrap();
    assert!(view.desired.contains(&instance.route));
    assert_eq!(view.owners[&instance.route].member_id, "m1");
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        0
    );
    assert_eq!(
        other.load_material(&record.payload).await.unwrap(),
        instance.launch_material
    );
    let wrong_owner = wire::SecretOwner {
        workspace: "default".into(),
        provider_id: instance.route.clone(),
        credential_key: LAUNCH_MATERIAL_KEY.into(),
        ..Default::default()
    };
    assert_eq!(
        fixture
            .issuer
            .raw
            .resolve_secrets(wire::ResolveSecretsRequest {
                purpose: wire::ResolvePurpose::MetadataInspection as i32,
                secrets: vec![wire::ResolveSecretRequest {
                    owner: Some(wrong_owner),
                    reference: reference.clone(),
                    request_id: "wrong-owner".into(),
                    expected_version: None
                }],
            })
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    other.controller.unassign(&instance.route);
    other.reconcile_once().await.unwrap();
    assert!(fixture.fixture.instance(&instance.route).await.is_none());
    assert_eq!(
        fixture
            .metadata(&instance.route, &reference)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert!(fixture.fixture.credentials.issuer_drivers().0.is_empty());
}

#[tokio::test]
async fn closing_issuer_intent_fences_the_actual_paused_supervisor_publisher() {
    let fixture = IssuerFixture::new().await;
    fixture
        .fixture
        .sandbox("paused-issuer-sandbox", "generation-1", SandboxPhase::Ready)
        .await;
    let pool = fixture.fixture.replica("issuer-paused-writer");
    let instance = assignment("rt-paused-issuer", "paused-issuer-sandbox", "generation-1");
    let (staged, resume) = pool.pause_next_recording_after_staging();
    let recording = {
        let pool = pool.clone();
        let instance = instance.clone();
        tokio::spawn(async move { pool.record_assignment(&instance).await })
    };
    tokio::time::timeout(Duration::from_secs(5), staged)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture
            .fixture
            .instance(&instance.route)
            .await
            .unwrap()
            .payload
            .phase,
        RecordPhase::Reserved
    );
    fixture.intent(&instance.route, "staging").await;
    let candidates = fixture
        .fixture
        .store
        .list_by_type(MATERIAL_CANDIDATE_OBJECT_TYPE, 128, 0)
        .await
        .unwrap();
    assert_eq!(candidates.len(), 1);
    let candidate: serde_json::Value = serde_json::from_slice(&candidates[0].payload).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(candidate["material_handle"].clone()).unwrap();
    let reference = reference_from_handle(&bytes);
    assert!(fixture.metadata(&instance.route, &reference).await.is_ok());
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        1
    );
    fixture.intent(&instance.route, "closed").await;
    resume.send(()).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), recording)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(fixture.fixture.instance(&instance.route).await.is_none());
    assert_eq!(fixture.fixture.candidates().await, 0);
    assert_eq!(
        fixture
            .metadata(&instance.route, &reference)
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        fixture
            .source
            .recover_internal_page(None, 32, i64::MAX)
            .await
            .unwrap()
            .cleaned,
        0
    );
    // A fresh reservation may own a new reference, never resurrect the closed
    // operation or publish the stale candidate that was just reclaimed.
    let next = pool.record_assignment(&instance).await.unwrap();
    assert_ne!(
        reference_from_handle(&next.payload.material_handle),
        reference
    );
    fixture
        .issuer
        .watched
        .wait_synchronized(Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(
        pool.load_material(&next.payload).await.unwrap(),
        instance.launch_material
    );
}
