// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    backend::CredentialDriver,
    mint_spool::MintResultSpool,
    minter::{
        MaterialDescriptor, MintFailure, MintRequest, MintResponse, MinterRegistry, TokenMinter,
    },
    remote_issuer::RemoteIssuer,
    repository::Repository,
    service::CredentialStoreService,
    storage::CredentialStorage,
};
use openshell_core::proto::{
    CredentialHandle,
    credentials::{
        store::v1 as wire,
        v1::{
            DeleteCredentialRequest, ResolveCredentialRequest, ResolvedCredential,
            StoreCredentialRequest,
        },
    },
};
use openshell_driver_db_credstore::{
    DbCredstoreCredentialDriver, EncryptedGatewayCredentialStoreCrypto,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tonic::Code;

#[derive(Debug, Default)]
struct Minter(AtomicUsize, AtomicBool);
#[tonic::async_trait]
impl TokenMinter for Minter {
    fn describe(&self) -> StrategyDescriptor {
        StrategyDescriptor {
            name: "custom:legacy".into(),
            config: vec![],
            secret_material: vec![MaterialDescriptor {
                name: "refresh_token".into(),
                required: true,
            }],
            outputs: vec!["token".into()],
            rotated_secret_material: vec!["refresh_token".into()],
        }
    }
    async fn mint(&self, _: MintRequest) -> Result<MintResponse, MintFailure> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert!(
            self.1.load(Ordering::SeqCst),
            "migration must never call a minter"
        );
        Ok(MintResponse {
            outputs: std::collections::HashMap::from([("token".into(), "new-token".into())]),
            expiration_time_ms: openshell_core::time::now_ms() + 60_000,
            rotated_secret_material: std::collections::HashMap::new(),
        })
    }
}
#[derive(Debug)]
struct Driver {
    inner: DbCredstoreCredentialDriver,
    fail: AtomicBool,
    stores: AtomicUsize,
    pause_on_store: AtomicUsize,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
#[tonic::async_trait]
impl CredentialDriver for Driver {
    async fn store_credential(
        &self,
        request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        let call = self.stores.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.pause_on_store.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        let handle = self.inner.store_credential(request).await?;
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(Status::unavailable("uncertain backend allocation"));
        }
        Ok(handle)
    }
    async fn delete_credential(&self, request: DeleteCredentialRequest) -> Result<(), Status> {
        self.inner.delete_credential(request).await
    }
    async fn resolve_credentials(
        &self,
        request: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        self.inner.resolve_credentials(request).await
    }
}
struct Fixture {
    host: CredentialStoreService,
    refresh: CredentialRefreshService,
    client: RemoteIssuer,
    input: LegacyGrant,
    minter: Arc<Minter>,
    driver: Arc<Driver>,
    repository: Arc<Repository>,
    _dir: tempfile::TempDir,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repository = Repository::open("sqlite::memory:").await.unwrap();
        let config = toml::Table::from_iter([(
            "key_encryption_key_path".into(),
            toml::Value::String(dir.path().join("key").display().to_string()),
        )]);
        let driver = Arc::new(Driver {
            inner: DbCredstoreCredentialDriver::from_config(repository.backend_objects(), &config)
                .unwrap(),
            fail: AtomicBool::new(false),
            stores: AtomicUsize::new(0),
            pause_on_store: AtomicUsize::new(usize::MAX),
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        let erased: Arc<dyn CredentialDriver> = driver.clone();
        let storage =
            CredentialStorage::new(BTreeMap::from([("db".into(), erased)]), "db".into()).unwrap();
        let host = CredentialStoreService::embedded(
            repository.clone(),
            storage,
            std::time::Duration::ZERO,
        )
        .unwrap();
        let minter = Arc::new(Minter::default());
        let mut minters = MinterRegistry::default();
        minters.register_custom(minter.clone()).unwrap();
        let refresh = CredentialRefreshService::new(
            &host,
            Arc::new(minters),
            MintResultSpool::new(
                EncryptedGatewayCredentialStoreCrypto::from_config(&config).unwrap(),
            ),
        )
        .unwrap();
        let client = RemoteIssuer::embedded(host.clone(), refresh.clone())
            .await
            .unwrap();
        let owner = crate::SecretOwner {
            workspace: "workspace".into(),
            provider_id: "provider".into(),
            credential_key: "TOKEN".into(),
            ..Default::default()
        };
        let wire_owner = wire::SecretOwner {
            workspace: owner.workspace.clone(),
            provider_id: owner.provider_id.clone(),
            credential_key: owner.credential_key.clone(),
            ..Default::default()
        };
        let mut output = client
            .put_secret(wire::PutSecretRequest {
                owner: Some(wire_owner.clone()),
                value: "already-published".into(),
                idempotency_key: "output".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        for version in 1..3 {
            output = client
                .put_secret(wire::PutSecretRequest {
                    owner: Some(wire_owner.clone()),
                    reference: output.reference,
                    expected_version: Some(version),
                    value: "already-published".into(),
                    idempotency_key: format!("output-{version}"),
                    ..Default::default()
                })
                .await
                .unwrap();
        }
        let input = LegacyGrant {
            identity: GrantIdentity {
                id: "legacy-grant".into(),
                authorization_epoch: "legacy-epoch".into(),
                owner,
            },
            source_revision: 12,
            source_provider_version: 9,
            descriptor: minter.describe(),
            outputs: BTreeMap::from([(
                "token".into(),
                LegacyGrantOutput {
                    binding: OutputBinding {
                        credential_key: "TOKEN".into(),
                        reference: output.reference,
                    },
                    version: 3,
                },
            )]),
            config: BTreeMap::new(),
            secret_material: BTreeMap::from([(
                "refresh_token".into(),
                "private-refresh-material".into(),
            )]),
            refresh_before_ms: 0,
            max_lifetime_seconds: 3600,
            status: LegacyGrantStatus {
                version: 12,
                phase: GrantPhase::Refreshed,
                expiration_time_ms: None,
                next_refresh_at_ms: i64::MAX,
                recovery_action: None,
                failure_code: String::new(),
                last_refresh_time_ms: Some(1000),
                last_error_time_ms: None,
                provider_error_subtype: String::new(),
                attempt_id: None,
                completed_attempt: Some("old-completed".into()),
                uncertain: false,
            },
            retired: Vec::new(),
        };
        Self {
            host,
            refresh,
            client,
            input,
            minter,
            driver,
            repository,
            _dir: dir,
        }
    }
    async fn state(&self) -> GrantState {
        self.repository
            .grants(&self.host.embedded_scope().unwrap())
            .load(&self.input.identity.id)
            .await
            .unwrap()
            .unwrap()
            .state
    }
    async fn claim_record(&self) -> crate::repository::Record {
        self.repository
            .for_gateway(&self.host.embedded_scope().unwrap())
            .load(CLAIM_KIND, &self.input.identity.id)
            .await
            .unwrap()
            .unwrap()
    }
    async fn claim(&self) -> Claim {
        decode(&self.claim_record().await.payload).unwrap()
    }
    async fn archives(&self) -> Vec<AbandonedClaim> {
        self.repository
            .for_gateway(&self.host.embedded_scope().unwrap())
            .list(ABANDONED_KIND, None, 128)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, record)| decode(&record.payload).unwrap())
            .collect()
    }
    async fn backing_value(&self, purpose: &str, backing: &[u8]) -> Result<String, Status> {
        self.host
            .runtime
            .storage
            .resolve(
                &self.host.embedded_scope().unwrap(),
                &self.input.identity.owner,
                purpose,
                backing,
            )
            .await
            .map(|value| value.value)
    }
}

#[tokio::test]
async fn imports_identity_epoch_reference_versions_and_history_without_remint_or_output_copy() {
    let fixture = Fixture::new().await;
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    assert_eq!(
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap(),
        "legacy-grant"
    );
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    let state = fixture.state().await;
    assert_eq!(state.definition.identity, fixture.input.identity);
    assert_eq!(state.version, 12);
    assert_eq!(state.phase, GrantPhase::Refreshed);
    assert_eq!(state.completed_attempt.as_deref(), Some("old-completed"));
    assert_eq!(state.last_refresh_time_ms, Some(1000));
    assert_eq!(
        fixture.driver.stores.load(Ordering::SeqCst) - stores,
        2,
        "only config/material are staged"
    );
    let output = &fixture.input.outputs["token"];
    let observed = fixture
        .host
        .legacy_reference_state(&output.binding.reference, &fixture.input.identity.owner)
        .await
        .unwrap();
    assert_eq!(observed.version, 3);
    let value = fixture
        .client
        .resolve_secrets(wire::ResolveSecretsRequest {
            secrets: vec![wire::ResolveSecretRequest {
                request_id: "one".into(),
                reference: output.binding.reference.clone(),
                owner: Some(wire::SecretOwner {
                    workspace: "workspace".into(),
                    provider_id: "provider".into(),
                    credential_key: "TOKEN".into(),
                    ..Default::default()
                }),
                expected_version: Some(3),
            }],
            purpose: wire::ResolvePurpose::SandboxDelivery as i32,
        })
        .await
        .unwrap();
    assert_eq!(value.secrets[0].value, "already-published");
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
    let scope = fixture.host.embedded_scope().unwrap();
    assert!(
        fixture
            .repository
            .for_gateway(&scope)
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        fixture
            .repository
            .for_gateway(&scope)
            .load(grants::OUTPUT_BINDING_KIND, &output.binding.reference)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn completed_import_replays_without_staging_and_never_returns_another_owner_or_epoch() {
    let fixture = Fixture::new().await;
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    assert_eq!(fixture.driver.stores.load(Ordering::SeqCst), stores);
    for change in 0..3 {
        let mut input = fixture.input.clone();
        match change {
            0 => input.identity.owner.provider_id = "replacement".into(),
            1 => input.identity.authorization_epoch = "replacement".into(),
            _ => input.source_revision += 1,
        }
        assert!(fixture.refresh.import_legacy_grant(input).await.is_err());
    }
    assert_eq!(fixture.driver.stores.load(Ordering::SeqCst), stores);
}

#[tokio::test]
async fn uncertain_inflight_legacy_mint_is_parked_and_its_attempt_marker_is_retained() {
    let mut fixture = Fixture::new().await;
    fixture.input.status.phase = GrantPhase::Publishing;
    fixture.input.status.attempt_id = Some("uncertain-attempt".into());
    fixture.input.status.uncertain = true;
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    let state = fixture.state().await;
    assert_eq!(state.phase, GrantPhase::Parked);
    assert_eq!(state.recovery_action, Some(RecoveryAction::Investigate));
    assert_eq!(state.next_refresh_at_ms, i64::MAX);
    assert_eq!(state.failure_code, "mint_outcome_unknown");
    assert_eq!(state.attempt.unwrap().id, "uncertain-attempt");
    fixture.minter.1.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .client
            .rotate_grant(
                openshell_core::proto::credentials::refresh::v1::RotateGrantRequest {
                    grant: fixture.input.identity.id.clone(),
                    idempotency_key: "uncertain-rotation".into(),
                },
            )
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition,
    );
    fixture.refresh.runtime.tick().await.unwrap();
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn uncertain_backend_allocation_is_durably_claimed_and_never_automatically_repeated() {
    let fixture = Fixture::new().await;
    fixture.driver.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    let scope = fixture.host.embedded_scope().unwrap();
    let claim = fixture
        .repository
        .for_gateway(&scope)
        .load(CLAIM_KIND, &fixture.input.identity.id)
        .await
        .unwrap()
        .unwrap();
    let claim: Claim = decode(&claim.payload).unwrap();
    assert!(claim.started.is_some());
    assert!(!claim.completed);
    assert_eq!(
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(fixture.driver.stores.load(Ordering::SeqCst), stores);
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn restart_recovers_a_journaled_candidate_without_allocating_it_again() {
    let fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let store = fixture.repository.for_gateway(&scope);
    let id = &fixture.input.identity.id;
    let operation = format!("legacy-grant:{id}");
    let purpose = config_purpose(&imported_state(&fixture.input));
    let claim = Claim {
        intent: import_intent(&fixture.input).unwrap(),
        identity: fixture.input.identity.clone(),
        candidate_operation: None,
        started: Some(purpose.clone()),
        staged: BTreeMap::new(),
        completed: false,
        activated: false,
        abandoned: false,
        prepared: None,
        output_versions: BTreeMap::new(),
    };
    store
        .commit(
            &[Mutation::Put {
                kind: CLAIM_KIND.into(),
                key: id.clone(),
                expected: None,
                payload: encode(&claim).unwrap(),
            }],
            &[],
        )
        .await
        .unwrap();
    fixture
        .refresh
        .runtime
        .store
        .stage_candidate(
            &scope,
            &fixture.input.identity.owner,
            &operation,
            &purpose,
            "{}".into(),
        )
        .await
        .unwrap();
    // Simulate restart after the candidate journal committed but before its
    // opaque backing was attached to the source claim.
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture.driver.stores.load(Ordering::SeqCst) - stores,
        1,
        "only the remaining material is staged"
    );
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture.state().await.definition.identity,
        fixture.input.identity
    );
    assert!(
        store
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
    let claim = store.load(CLAIM_KIND, id).await.unwrap().unwrap();
    assert!(!String::from_utf8_lossy(&claim.payload).contains("private-refresh-material"));
    assert!(decode::<Claim>(&claim.payload).unwrap().completed);
}

#[tokio::test]
async fn dormant_import_is_invisible_to_rpc_scheduler_and_cleanup_until_publication_ack() {
    let mut fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let purpose = "legacy-source-material";
    let backing = fixture
        .host
        .runtime
        .storage
        .stage(
            &scope,
            &fixture.input.identity.owner,
            purpose,
            "still-owned-by-legacy-dto".into(),
        )
        .await
        .unwrap();
    fixture.input.retired.push(RetiredBacking {
        owner: fixture.input.identity.owner.clone(),
        purpose: purpose.into(),
        backing: backing.clone(),
    });
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    let pending = fixture
        .refresh
        .pending_legacy_grants(None, 128)
        .await
        .unwrap();
    assert_eq!(pending.grants.len(), 1);
    assert_eq!(pending.grants[0].identity, fixture.input.identity);
    assert_eq!(
        pending.grants[0].outputs["token"],
        fixture.input.outputs["token"].binding
    );
    assert_eq!(
        fixture
            .client
            .get_grant(super::super::wire::GetGrantRequest {
                grant: fixture.input.identity.id.clone()
            })
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    fixture.refresh.runtime.tick().await.unwrap();
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture
            .host
            .runtime
            .storage
            .resolve(&scope, &fixture.input.identity.owner, purpose, &backing)
            .await
            .unwrap()
            .value,
        "still-owned-by-legacy-dto"
    );
    let mut wrong = fixture.input.identity.clone();
    wrong.authorization_epoch = "replacement".into();
    assert_eq!(
        fixture
            .refresh
            .activate_legacy_grant(wrong)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    assert!(
        fixture
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );
    assert_eq!(fixture.state().await.version, fixture.input.status.version);
    fixture.refresh.runtime.tick().await.unwrap();
    assert!(
        fixture
            .host
            .runtime
            .storage
            .resolve(&scope, &fixture.input.identity.owner, purpose, &backing)
            .await
            .is_err()
    );
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn activation_cannot_publish_a_snapshot_after_an_output_version_changed() {
    let fixture = Fixture::new().await;
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    let output = &fixture.input.outputs["token"];
    fixture
        .client
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "workspace".into(),
                provider_id: "provider".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
            reference: output.binding.reference.clone(),
            value: "newer-legacy-value".into(),
            expected_version: Some(3),
            idempotency_key: "changed-before-activation".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(
        fixture
            .refresh
            .activate_legacy_grant(fixture.input.identity.clone())
            .await
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert_eq!(
        fixture
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .len(),
        1
    );
    assert!(
        fixture
            .repository
            .grants(&fixture.host.embedded_scope().unwrap())
            .load(&fixture.input.identity.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn changed_dormant_generation_retires_only_native_copies_and_preserves_legacy_authority() {
    let mut fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let purpose = material_purpose(&imported_state(&fixture.input), "refresh_token");
    let legacy_backing = fixture
        .host
        .runtime
        .storage
        .stage(
            &scope,
            &fixture.input.identity.owner,
            &purpose,
            "legacy-dto-still-owns-this".into(),
        )
        .await
        .unwrap();
    fixture.input.retired.push(RetiredBacking {
        owner: fixture.input.identity.owner.clone(),
        purpose: purpose.clone(),
        backing: legacy_backing.clone(),
    });
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    let old_revision = fixture.claim_record().await.revision;
    let old_prepared = fixture.claim().await.prepared.unwrap();
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    let mut current = fixture.input.clone();
    current.source_provider_version += 1;
    fixture
        .refresh
        .replace_legacy_grant(current.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture.driver.stores.load(Ordering::SeqCst),
        stores,
        "a provider metadata-only revision must not replace native material"
    );
    assert!(fixture.archives().await.is_empty());
    assert_eq!(fixture.claim_record().await.revision, old_revision);

    let output = &fixture.input.outputs["token"].binding.reference;
    fixture
        .client
        .put_secret(wire::PutSecretRequest {
            owner: Some(wire::SecretOwner {
                workspace: "workspace".into(),
                provider_id: "provider".into(),
                credential_key: "TOKEN".into(),
                ..Default::default()
            }),
            reference: output.clone(),
            value: "old-replica-published-new-output".into(),
            expected_version: Some(3),
            idempotency_key: "late-legacy-refresh".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    current.source_revision += 1;
    current.status.version += 1;
    current.outputs.get_mut("token").unwrap().version = 4;
    current
        .secret_material
        .insert("refresh_token".into(), "current-refresh-material".into());
    fixture
        .refresh
        .replace_legacy_grant(current.clone())
        .await
        .unwrap();
    assert!(fixture.claim_record().await.revision > old_revision);
    let archives = fixture.archives().await;
    assert_eq!(archives.len(), 1);
    assert_eq!(archives[0].claim.identity, fixture.input.identity);
    assert_eq!(archives[0].cleanup_candidates.len(), 2);
    let prepared = fixture.claim().await.prepared.unwrap();
    assert_ne!(
        prepared.material["refresh_token"],
        old_prepared.material["refresh_token"]
    );
    assert_eq!(
        fixture
            .backing_value(&purpose, &prepared.material["refresh_token"])
            .await
            .unwrap(),
        "current-refresh-material"
    );
    fixture.host.runtime.maintenance().await.unwrap();
    assert!(
        fixture
            .backing_value(
                &config_purpose(&old_prepared),
                &old_prepared.definition.config_backing
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .backing_value(&purpose, &old_prepared.material["refresh_token"])
            .await
            .is_err()
    );
    assert_eq!(
        fixture
            .backing_value(&purpose, &legacy_backing)
            .await
            .unwrap(),
        "legacy-dto-still-owns-this"
    );
    assert_eq!(
        fixture
            .backing_value(&purpose, &prepared.material["refresh_token"])
            .await
            .unwrap(),
        "current-refresh-material"
    );
    let observed = fixture
        .host
        .legacy_reference_state(output, &fixture.input.identity.owner)
        .await
        .unwrap();
    assert_eq!(observed.version, 4);
    assert!(!observed.revoked);
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
    fixture
        .refresh
        .activate_legacy_grant(current.identity)
        .await
        .unwrap();
    assert_eq!(fixture.state().await.version, current.status.version);
}

#[tokio::test]
async fn explicit_abandonment_is_idempotent_and_stale_activation_cannot_pass_an_aba_cas() {
    let fixture = Fixture::new().await;
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    let old_record = fixture.claim_record().await;
    let mut old_claim: Claim = decode(&old_record.payload).unwrap();
    let old_state = old_claim.prepared.take().unwrap();
    let mut wrong = fixture.input.identity.clone();
    wrong.authorization_epoch = "wrong-epoch".into();
    assert_eq!(
        fixture
            .refresh
            .abandon_legacy_grant(wrong)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    fixture
        .refresh
        .abandon_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    let abandoned_revision = fixture.claim_record().await.revision;
    assert!(abandoned_revision > old_record.revision);
    assert!(fixture.claim().await.abandoned);
    fixture
        .refresh
        .abandon_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    assert_eq!(fixture.claim_record().await.revision, abandoned_revision);
    assert_eq!(fixture.archives().await.len(), 1);
    assert_eq!(
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .refresh
            .activate_legacy_grant(fixture.input.identity.clone())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert!(
        fixture
            .refresh
            .pending_legacy_grants(None, 128)
            .await
            .unwrap()
            .grants
            .is_empty()
    );

    let mut replacement = fixture.input.clone();
    replacement.source_revision += 1;
    replacement.identity.authorization_epoch = "current-epoch".into();
    fixture
        .refresh
        .replace_legacy_grant(replacement.clone())
        .await
        .unwrap();
    assert!(fixture.claim_record().await.revision > abandoned_revision);
    let store = fixture
        .repository
        .for_gateway(&fixture.host.embedded_scope().unwrap());
    old_claim.activated = true;
    // A stale activation may know an old source-row revision and all its
    // backing handles. Its native grant insertion MUST roll back with the CAS.
    let stale = store
        .commit(
            &[
                Mutation::Put {
                    kind: grants::KIND.into(),
                    key: fixture.input.identity.id.clone(),
                    expected: None,
                    payload: encode(&old_state).unwrap(),
                },
                Mutation::Put {
                    kind: CLAIM_KIND.into(),
                    key: fixture.input.identity.id.clone(),
                    expected: Some(old_record.revision),
                    payload: encode(&old_claim).unwrap(),
                },
            ],
            &[],
        )
        .await
        .unwrap_err();
    assert_eq!(stale.code(), Code::Aborted);
    assert!(
        fixture
            .repository
            .grants(&fixture.host.embedded_scope().unwrap())
            .load(&fixture.input.identity.id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(fixture.claim().await.identity, replacement.identity);
    fixture.host.runtime.maintenance().await.unwrap();
    fixture
        .refresh
        .activate_legacy_grant(replacement.identity.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture.state().await.definition.identity,
        replacement.identity
    );
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn activated_native_authority_is_never_replaced_abandoned_or_queued_for_cleanup() {
    let fixture = Fixture::new().await;
    fixture
        .refresh
        .import_legacy_grant(fixture.input.clone())
        .await
        .unwrap();
    fixture
        .refresh
        .activate_legacy_grant(fixture.input.identity.clone())
        .await
        .unwrap();
    let before = fixture.state().await;
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    let mut changed = fixture.input.clone();
    changed.source_revision += 1;
    changed
        .secret_material
        .insert("refresh_token".into(), "new-but-unauthorized".into());
    assert_eq!(
        fixture
            .refresh
            .replace_legacy_grant(changed)
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        fixture
            .refresh
            .abandon_legacy_grant(fixture.input.identity.clone())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(fixture.driver.stores.load(Ordering::SeqCst), stores);
    assert!(fixture.archives().await.is_empty());
    let after = fixture.state().await;
    assert!(after.definition == before.definition);
    assert_eq!(after.version, before.version);
    assert_eq!(after.material, before.material);
    let scope = fixture.host.embedded_scope().unwrap();
    assert!(
        fixture
            .repository
            .for_gateway(&scope)
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        !fixture
            .host
            .legacy_reference_state(
                &fixture.input.outputs["token"].binding.reference,
                &fixture.input.identity.owner
            )
            .await
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn replacement_keeps_unattached_candidate_cleanup_and_unresolved_allocation_evidence() {
    let fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let store = fixture.repository.for_gateway(&scope);
    let purpose = config_purpose(&imported_state(&fixture.input));
    let mut claim = Claim::pending(
        fixture.input.identity.clone(),
        import_intent(&fixture.input).unwrap(),
    );
    let operation = claim.candidate_operation.clone().unwrap();
    claim.started = Some(purpose.clone());
    store
        .commit(
            &[Mutation::Put {
                kind: CLAIM_KIND.into(),
                key: fixture.input.identity.id.clone(),
                expected: None,
                payload: encode(&claim).unwrap(),
            }],
            &[],
        )
        .await
        .unwrap();
    let (_, old_backing) = fixture
        .refresh
        .runtime
        .store
        .stage_candidate(
            &scope,
            &fixture.input.identity.owner,
            &operation,
            &purpose,
            "{}".into(),
        )
        .await
        .unwrap();
    let mut next = fixture.input.clone();
    next.source_revision += 1;
    fixture
        .refresh
        .replace_legacy_grant(next.clone())
        .await
        .unwrap();
    let archived = fixture.archives().await;
    assert_eq!(archived.len(), 1);
    assert_eq!(archived[0].claim.started.as_deref(), Some(purpose.as_str()));
    assert!(archived[0].claim.staged.is_empty());
    let prepared = fixture.claim().await.prepared.unwrap();
    fixture.host.runtime.maintenance().await.unwrap();
    assert!(fixture.backing_value(&purpose, &old_backing).await.is_err());
    assert_eq!(
        fixture
            .backing_value(&purpose, &prepared.definition.config_backing)
            .await
            .unwrap(),
        "{}"
    );
    fixture
        .refresh
        .activate_legacy_grant(next.identity)
        .await
        .unwrap();
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replacement_crash_never_recovers_a_late_candidate_from_the_previous_generation() {
    let fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let store = fixture.repository.for_gateway(&scope);
    let id = &fixture.input.identity.id;
    let old_operation = format!("legacy-grant:{id}");
    let purpose = material_purpose(&imported_state(&fixture.input), "refresh_token");
    let mut old = Claim::pending(
        fixture.input.identity.clone(),
        import_intent(&fixture.input).unwrap(),
    );
    // Model a pre-generation claim with an allocation still in flight.
    old.candidate_operation = None;
    old.started = Some(purpose.clone());
    store
        .commit(
            &[Mutation::Put {
                kind: CLAIM_KIND.into(),
                key: id.clone(),
                expected: None,
                payload: encode(&old).unwrap(),
            }],
            &[],
        )
        .await
        .unwrap();
    let mut current = fixture.input.clone();
    current.source_revision += 1;
    current
        .secret_material
        .insert("refresh_token".into(), "current-private".into());
    fixture
        .refresh
        .abandon_dormant_generation(
            scope.clone(),
            id.clone(),
            None,
            Some(Replacement {
                identity: current.identity.clone(),
                intent: import_intent(&current).unwrap(),
            }),
        )
        .await
        .unwrap();
    let record = fixture.claim_record().await;
    let mut claim = fixture.claim().await;
    let current_operation = claim.candidate_operation.clone().unwrap();
    assert_ne!(current_operation, old_operation);
    // New generation persists its allocation intent, then crashes before it
    // invokes the driver. The previous uncertain allocation journals AFTER this.
    claim.started = Some(purpose.clone());
    save_claim(&store, id, record.revision, &claim)
        .await
        .unwrap();
    let (_, stale_backing) = fixture
        .host
        .runtime
        .stage_candidate(
            &scope,
            &current.identity.owner,
            &old_operation,
            &purpose,
            "stale-private".into(),
        )
        .await
        .unwrap();
    let stores = fixture.driver.stores.load(Ordering::SeqCst);
    assert_eq!(
        fixture
            .refresh
            .import_legacy_grant(current.clone())
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition,
        "the sole old candidate cannot satisfy the new pre-allocation intent",
    );
    assert_eq!(fixture.driver.stores.load(Ordering::SeqCst), stores);
    assert!(!fixture.claim().await.completed);
    assert_eq!(
        fixture.claim().await.candidate_operation.as_deref(),
        Some(current_operation.as_str())
    );
    assert_eq!(
        fixture.archives().await[0].claim.started.as_deref(),
        Some(purpose.as_str())
    );
    // A candidate actually journaled by THIS generation may be recovered.
    fixture
        .host
        .runtime
        .stage_candidate(
            &scope,
            &current.identity.owner,
            &current_operation,
            &purpose,
            "current-private".into(),
        )
        .await
        .unwrap();
    fixture
        .refresh
        .import_legacy_grant(current.clone())
        .await
        .unwrap();
    let prepared = fixture.claim().await.prepared.unwrap();
    assert_ne!(prepared.material["refresh_token"], stale_backing);
    assert_eq!(
        fixture
            .backing_value(&purpose, &prepared.material["refresh_token"])
            .await
            .unwrap(),
        "current-private"
    );
    fixture.host.runtime.maintenance().await.unwrap();
    assert!(
        fixture
            .backing_value(&purpose, &stale_backing)
            .await
            .is_err()
    );
    fixture
        .refresh
        .activate_legacy_grant(current.identity)
        .await
        .unwrap();
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn active_import_generation_excludes_candidate_maintenance_until_publication() {
    let fixture = Fixture::new().await;
    // Drain the fixture's retired output backings before capturing reference
    // revisions. This test targets candidate exclusion, not a valid reference
    // CAS conflict caused by concurrent cleanup-only metadata updates.
    fixture.host.runtime.maintenance().await.unwrap();
    // Stop in the second driver call: the configuration candidate has already
    // been journaled and attached, but the import is not yet complete.
    fixture.driver.pause_on_store.store(
        fixture.driver.stores.load(Ordering::SeqCst) + 2,
        Ordering::SeqCst,
    );
    let refresh = fixture.refresh.clone();
    let input = fixture.input.clone();
    let importing = tokio::spawn(async move { refresh.import_legacy_grant(input).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        fixture.driver.entered.notified(),
    )
    .await
    .unwrap();
    let scope = fixture.host.embedded_scope().unwrap();
    let store = fixture.repository.for_gateway(&scope);
    let claim = fixture.claim().await;
    let staged = claim.staged.values().next().unwrap();
    let operation = claim.candidate_operation.as_ref().unwrap();
    let record = store
        .load(CANDIDATE_KIND, &staged.candidate)
        .await
        .unwrap()
        .unwrap();
    let candidate: Candidate = decode(&record.payload).unwrap();
    assert_eq!(&candidate.operation_key, operation);
    fixture.host.runtime.maintenance().await.unwrap();
    assert_eq!(
        store
            .load(CANDIDATE_KIND, &staged.candidate)
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    fixture.driver.resume.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), importing)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(fixture.claim().await.completed);
    assert!(
        store
            .list(CANDIDATE_KIND, None, 128)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn original_import_identity_lookup_covers_partial_claims_but_rejects_another_owner() {
    let fixture = Fixture::new().await;
    let scope = fixture.host.embedded_scope().unwrap();
    let store = fixture.repository.for_gateway(&scope);
    let mut claim = Claim::pending(
        fixture.input.identity.clone(),
        import_intent(&fixture.input).unwrap(),
    );
    claim.started = Some(config_purpose(&imported_state(&fixture.input)));
    store
        .commit(
            &[Mutation::Put {
                kind: CLAIM_KIND.into(),
                key: fixture.input.identity.id.clone(),
                expected: None,
                payload: encode(&claim).unwrap(),
            }],
            &[],
        )
        .await
        .unwrap();
    let observed = fixture
        .refresh
        .legacy_grant_import_identity(&fixture.input.identity.id, &fixture.input.identity.owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed, fixture.input.identity);
    let mut wrong = fixture.input.identity.owner.clone();
    wrong.provider_id = "other-provider".into();
    assert_eq!(
        fixture
            .refresh
            .legacy_grant_import_identity(&fixture.input.identity.id, &wrong)
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    fixture
        .refresh
        .abandon_legacy_grant(observed)
        .await
        .unwrap();
    assert!(fixture.claim().await.abandoned);
}

#[tokio::test]
async fn legacy_long_schedules_survive_import_activation_and_repository_reload() {
    for lifetime in [
        86_400,
        i64::from(u32::MAX) + 1,
        openshell_core::time::MAX_DURATION_SECONDS + 1,
    ] {
        let mut fixture = Fixture::new().await;
        fixture.input.max_lifetime_seconds = lifetime;
        fixture.input.refresh_before_ms = 46_800_000;
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap();
        assert_eq!(
            fixture
                .refresh
                .pending_legacy_grants(None, 128)
                .await
                .unwrap()
                .grants
                .len(),
            1
        );
        fixture
            .refresh
            .activate_legacy_grant(fixture.input.identity.clone())
            .await
            .unwrap();
        let state = fixture.state().await;
        assert_eq!(state.definition.max_lifetime_seconds, lifetime);
        assert_eq!(state.definition.refresh_before_ms, 46_800_000);
        assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn classified_investigation_import_retains_backoff_and_both_retry_paths() {
    use openshell_core::proto::credentials::refresh::v1 as refresh;
    for automatic in [true, false] {
        let mut fixture = Fixture::new().await;
        let now = openshell_core::time::now_ms();
        fixture.input.status.phase = GrantPhase::Failed;
        fixture.input.status.recovery_action = Some(RecoveryAction::Investigate);
        fixture.input.status.failure_code = "refresh_failed".into();
        fixture.input.status.next_refresh_at_ms = now + 60_000;
        fixture.input.status.expiration_time_ms = Some(now - 1000);
        fixture.input.status.attempt_id = Some("classified-failed-attempt".into());
        fixture
            .refresh
            .import_legacy_grant(fixture.input.clone())
            .await
            .unwrap();
        fixture
            .refresh
            .activate_legacy_grant(fixture.input.identity.clone())
            .await
            .unwrap();
        let state = fixture.state().await;
        assert_eq!(state.phase, GrantPhase::Failed);
        assert_eq!(state.next_refresh_at_ms, now + 60_000);
        assert_eq!(state.recovery_action, Some(RecoveryAction::Investigate));
        assert!(
            state.attempt.is_none(),
            "a classified failure has no unresolved exchange"
        );
        fixture.minter.1.store(true, Ordering::SeqCst);
        fixture.refresh.runtime.tick().await.unwrap();
        assert_eq!(
            fixture.minter.0.load(Ordering::SeqCst),
            0,
            "automatic work honors backoff"
        );
        if automatic {
            let scope = fixture.host.embedded_scope().unwrap();
            let loaded = fixture
                .repository
                .grants(&scope)
                .load(&fixture.input.identity.id)
                .await
                .unwrap()
                .unwrap();
            let mut due = loaded.state;
            due.next_refresh_at_ms = now - 1;
            due.version += 1;
            fixture
                .refresh
                .runtime
                .save(&scope, loaded.revision, &due, Vec::new())
                .await
                .unwrap();
            fixture.refresh.runtime.tick().await.unwrap();
        } else {
            fixture
                .client
                .rotate_grant(refresh::RotateGrantRequest {
                    grant: fixture.input.identity.id.clone(),
                    idempotency_key: "classified-manual-retry".into(),
                })
                .await
                .unwrap();
        }
        assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 1);
        let refreshed = fixture.state().await;
        assert_eq!(refreshed.phase, GrantPhase::Refreshed);
        assert!(refreshed.recovery_action.is_none());
    }
}

#[tokio::test]
async fn native_create_and_reserve_still_reject_legacy_only_long_lifetimes() {
    use openshell_core::proto::credentials::refresh::v1 as refresh;
    let fixture = Fixture::new().await;
    let owner = Some(wire::SecretOwner {
        workspace: "workspace".into(),
        provider_id: "provider".into(),
        credential_key: "TOKEN".into(),
        ..Default::default()
    });
    let lifetime = Some(prost_types::Duration {
        seconds: 86_400,
        nanos: 0,
    });
    assert_eq!(
        fixture
            .client
            .reserve_grant(refresh::ReserveGrantRequest {
                owner: owner.clone(),
                strategy: "custom:legacy".into(),
                outputs: std::collections::HashMap::from([("token".into(), "TOKEN".into())]),
                max_lifetime: lifetime,
                idempotency_key: "new-reservation".into(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        fixture
            .client
            .create_grant(refresh::CreateGrantRequest {
                owner,
                strategy: "custom:legacy".into(),
                outputs: std::collections::HashMap::from([("token".into(), "TOKEN".into())]),
                secret_material: std::collections::HashMap::from([(
                    "refresh_token".into(),
                    "secret".into()
                )]),
                max_lifetime: lifetime,
                idempotency_key: "new-create".into(),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(fixture.minter.0.load(Ordering::SeqCst), 0);
}
