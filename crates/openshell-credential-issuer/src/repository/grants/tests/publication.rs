// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    ReferenceReplacement, grant::GrantAdmission, mint_spool::MintResultSpool, minter::MintResponse,
};
use openshell_driver_db_credstore::EncryptedGatewayCredentialStoreCrypto;
use std::collections::HashMap;

#[tokio::test]
async fn encrypted_known_result_reopens_and_publication_joins_outputs_and_completion_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("issuer.db").display()
    );
    publication_roundtrip(&url, directory.path()).await;
}

#[tokio::test]
#[ignore = "requires OPENSHELL_TEST_ISSUER_POSTGRES_URL"]
async fn postgres_grants_publish_known_results_and_receipts_across_independent_pools() {
    let url = std::env::var("OPENSHELL_TEST_ISSUER_POSTGRES_URL").unwrap();
    let directory = tempfile::tempdir().unwrap();
    publication_roundtrip(&url, directory.path()).await;
}

async fn publication_roundtrip(url: &str, directory: &std::path::Path) {
    let repository = Repository::open(url).await.unwrap();
    let scope = test_scope(&format!("grant-publication-{}", uuid::Uuid::new_v4()));
    let mut state = state();
    let baseline = state.checkpoint();
    let (grant, event) = repository
        .grants(&scope)
        .prepare(None, &state)
        .await
        .unwrap();
    let (reference, change) = repository
        .references(&scope)
        .prepare(
            "reference",
            None,
            &ReferenceState::reserved(state.definition.identity.owner.clone()),
        )
        .await
        .unwrap();
    repository
        .for_gateway(&scope)
        .commit(&[grant, reference], &[event.unwrap(), change.unwrap()])
        .await
        .unwrap();
    state.phase = GrantPhase::Refreshing;
    state.version = 2;
    state.attempt = Some(GrantAttempt {
        id: "attempt".into(),
        encrypted_result: None,
        expected_output_versions: BTreeMap::from([("access_token".into(), 1)]),
        output_candidates: BTreeMap::new(),
        material_candidates: BTreeMap::new(),
        rotation_receipt: None,
    });
    save(&repository, &scope, Some(1), &state).await.unwrap();
    let crypto = EncryptedGatewayCredentialStoreCrypto::from_config(&toml::Table::from_iter([(
        "key_encryption_key_path".into(),
        toml::Value::String(directory.join("key").to_str().unwrap().into()),
    )]))
    .unwrap();
    let spool = MintResultSpool::new(crypto);
    let response = MintResponse {
        outputs: HashMap::from([("access_token".into(), "secret-output".into())]),
        expiration_time_ms: 123_456,
        rotated_secret_material: HashMap::from([(
            "refresh_token".into(),
            "secret-new-refresh".into(),
        )]),
    };
    state.attempt.as_mut().unwrap().encrypted_result = Some(
        spool
            .seal(&scope, &state.definition.identity, "attempt", &response)
            .unwrap(),
    );
    state.phase = GrantPhase::Publishing;
    state.version = 3;
    save(&repository, &scope, Some(2), &state).await.unwrap();
    state
        .attempt
        .as_mut()
        .unwrap()
        .output_candidates
        .insert("access_token".into(), vec![4]);
    state
        .attempt
        .as_mut()
        .unwrap()
        .material_candidates
        .insert("refresh_token".into(), vec![5]);
    save(&repository, &scope, Some(3), &state).await.unwrap();
    let reopened = Repository::open(url).await.unwrap();
    let recovered = reopened
        .grants(&scope)
        .load("grant")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.revision, 4);
    let restored = spool
        .open(
            &scope,
            &recovered.state.definition.identity,
            "attempt",
            recovered
                .state
                .attempt
                .as_ref()
                .unwrap()
                .encrypted_result
                .as_ref()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        restored.rotated_secret_material["refresh_token"],
        "secret-new-refresh"
    );
    assert!(
        !String::from_utf8(
            reopened
                .for_gateway(&scope)
                .load(KIND, "grant")
                .await
                .unwrap()
                .unwrap()
                .payload
        )
        .unwrap()
        .contains("secret-new-refresh")
    );
    let mut completed = state.clone();
    completed.phase = GrantPhase::Refreshed;
    completed.version = 4;
    completed.attempt = None;
    completed.completed_attempt = Some("wrong-attempt".into());
    completed.expiration_time_ms = Some(123_456);
    completed.next_refresh_at_ms = 100_000;
    completed.material.insert("refresh_token".into(), vec![5]);
    completed.retired.push(RetiredBacking {
        owner: state.definition.identity.owner.clone(),
        purpose: "grant-material-v1".into(),
        backing: vec![2],
    });
    assert!(
        reopened
            .grants(&scope)
            .prepare(Some(4), &completed)
            .await
            .is_err()
    );
    completed.completed_attempt = Some("attempt".into());
    let refs = reopened.references(&scope);
    let writes = refs
        .registry()
        .prepare_replacements(&[ReferenceReplacement {
            reference: "reference".into(),
            owner: state.definition.identity.owner.clone(),
            expected_version: 1,
            backing: vec![4],
            expiration_time_ms: Some(123_456),
        }])
        .await
        .unwrap();
    let (mut mutations, mut changes) = refs.prepare_many(&writes).await.unwrap();
    let (mutation, event) = reopened
        .grants(&scope)
        .prepare(Some(4), &completed)
        .await
        .unwrap();
    mutations.push(mutation);
    changes.extend(event);
    let mut failing = mutations.clone();
    failing.push(Mutation::Check {
        kind: "owner-fence".into(),
        key: "missing".into(),
        expected: 1,
    });
    let store = reopened.for_gateway(&scope);
    let sequence = store.current_sequence().await.unwrap();
    assert!(store.commit(&failing, &changes).await.is_err());
    assert_eq!(store.current_sequence().await.unwrap(), sequence);
    assert!(
        refs.load("reference")
            .await
            .unwrap()
            .unwrap()
            .state
            .pending_value
    );
    assert_eq!(
        reopened
            .grants(&scope)
            .load("grant")
            .await
            .unwrap()
            .unwrap()
            .state
            .phase,
        GrantPhase::Publishing
    );
    store.commit(&mutations, &changes).await.unwrap();
    assert_eq!(
        refs.load("reference").await.unwrap().unwrap().state.version,
        2
    );
    let loaded = reopened
        .grants(&scope)
        .load("grant")
        .await
        .unwrap()
        .unwrap();
    assert!(loaded.state.attempt.is_none());
    assert_eq!(
        loaded.state.checkpoint().admit(&baseline).unwrap(),
        GrantAdmission::Current
    );
}
