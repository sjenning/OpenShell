// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use tokio::sync::Semaphore;
use tonic::{Code, transport::Channel};
fn client() -> RemoteIssuer {
    let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
    RemoteIssuer {
        store: store::credential_store_client::CredentialStoreClient::new(channel.clone()),
        refresh: refresh::credential_refresh_client::CredentialRefreshClient::new(channel),
        calls: Arc::new(Semaphore::new(16)),
        watches: Arc::new(Semaphore::new(2)),
        capabilities: store::GetCapabilitiesResponse {
            max_batch_size: 64,
            max_response_bytes: 1024 * 1024,
            ..Default::default()
        },
    }
}
fn inner() -> Inner {
    let (changes, _) = broadcast::channel(128);
    let (health, _) = watch::channel(WatchHealth::default());
    Inner {
        client: client(),
        state: Mutex::new(State {
            health: WatchHealth {
                secrets: true,
                grants: true,
                generation: 0,
            },
            ..Default::default()
        }),
        changes,
        health,
    }
}
fn request(reference: &str) -> store::ResolveSecretsRequest {
    store::ResolveSecretsRequest {
        secrets: vec![store::ResolveSecretRequest {
            request_id: reference.into(),
            owner: Some(store::SecretOwner {
                workspace: "default".into(),
                provider_id: "provider".into(),
                credential_key: "TOKEN".into(),
                provider: String::new(),
            }),
            reference: reference.into(),
            expected_version: Some(1),
        }],
        purpose: store::ResolvePurpose::SandboxDelivery as i32,
    }
}
fn response(reference: &str, value: &str) -> store::ResolveSecretsResponse {
    store::ResolveSecretsResponse {
        secrets: vec![store::ResolvedSecret {
            request_id: reference.into(),
            value: value.into(),
            version: 1,
            cache_ttl: Some(prost_types::Duration {
                seconds: 60,
                nanos: 0,
            }),
            ..Default::default()
        }],
    }
}
#[tokio::test]
async fn disconnects_resets_and_late_rpc_candidates_never_restore_stale_cached_values() {
    let inner = inner();
    let before = inner.lock().unwrap().health;
    cache::record(&inner, &request("ref"), &mut response("ref", "old"), before).unwrap();
    assert!(cache::get(&inner, &request("ref")).unwrap().is_some());
    inner.unknown(ChangeKind::Secrets).unwrap();
    assert!(cache::get(&inner, &request("ref")).unwrap().is_none());
    inner.ready(ChangeKind::Secrets).unwrap();
    let mut late = response("ref", "old");
    cache::record(&inner, &request("ref"), &mut late, before).unwrap();
    assert_eq!(late.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    assert!(cache::get(&inner, &request("ref")).unwrap().is_none());
    assert!(inner.lock().unwrap().secrets["ref"].metadata.is_none());
    inner.unknown(ChangeKind::Grants).unwrap();
    let disconnected = inner.lock().unwrap().health;
    let mut fresh = response("ref", "fresh");
    cache::record(&inner, &request("ref"), &mut fresh, disconnected).unwrap();
    assert_eq!(fresh.secrets[0].cache_ttl.as_ref().unwrap().seconds, 0);
    assert!(inner.lock().unwrap().secrets["ref"].metadata.is_some());
    inner.ready(ChangeKind::Grants).unwrap();
    assert!(cache::get(&inner, &request("ref")).unwrap().is_none());
}
#[tokio::test]
async fn one_changed_sibling_fences_the_entire_result_before_cache_publication() {
    let inner = inner();
    let before = inner.lock().unwrap().health;
    let mut inputs = request("one");
    inputs.secrets.extend(request("two").secrets);
    let mut values = response("one", "first");
    values.secrets.extend(response("two", "second").secrets);
    for input in &inputs.secrets {
        inner
            .track_secret(input.owner.clone().unwrap(), input.reference.clone())
            .unwrap();
    }
    inner
        .lock()
        .unwrap()
        .secrets
        .get_mut("two")
        .unwrap()
        .version = 2;
    assert_eq!(
        cache::record(&inner, &inputs, &mut values, before)
            .unwrap_err()
            .code(),
        Code::Aborted
    );
    assert!(inner.lock().unwrap().values.is_empty());
    assert!(inner.lock().unwrap().secrets["one"].metadata.is_none());
}
#[tokio::test]
async fn cache_keys_include_immutable_owner_purpose_and_pinned_versions() {
    let inner = inner();
    let before = inner.lock().unwrap().health;
    cache::record(
        &inner,
        &request("ref"),
        &mut response("ref", "value"),
        before,
    )
    .unwrap();
    let mut other = request("ref");
    other.secrets[0].owner.as_mut().unwrap().provider_id = "other".into();
    assert!(cache::get(&inner, &other).unwrap().is_none());
    assert!(
        inner
            .track_secret(other.secrets[0].owner.clone().unwrap(), "ref".into())
            .is_err()
    );
    let mut other = request("ref");
    other.purpose = store::ResolvePurpose::OperatorExport as i32;
    assert!(cache::get(&inner, &other).unwrap().is_none());
    other = request("ref");
    other.secrets[0].expected_version = Some(2);
    assert!(cache::get(&inner, &other).unwrap().is_none());
    other.secrets[0].expected_version = None;
    assert!(cache::get(&inner, &other).unwrap().is_none());
}
#[tokio::test]
async fn a_partial_cache_or_oversized_request_cannot_bypass_whole_batch_limits() {
    let inner = Arc::new(inner());
    let before = inner.lock().unwrap().health;
    cache::record(
        &inner,
        &request("ref"),
        &mut response("ref", "value"),
        before,
    )
    .unwrap();
    let mut partial = request("ref");
    partial.secrets.extend(request("missing").secrets);
    assert!(cache::get(&inner, &partial).unwrap().is_none());
    let source = WatchedIssuer {
        inner: inner.clone(),
        _workers: Arc::new(Workers(Vec::new())),
    };
    let mut large = request("ref");
    large.secrets[0].owner.as_mut().unwrap().provider = "x".repeat(super::super::LIMIT);
    assert_eq!(
        source.resolve_secrets(large).await.unwrap_err().code(),
        Code::ResourceExhausted
    );
    let mut audit = request("audit").secrets.remove(0).owner.unwrap();
    audit.provider = "x".repeat(super::super::LIMIT);
    inner.track_secret(audit, "audit".into()).unwrap();
    assert_eq!(
        inner.lock().unwrap().secrets["audit"]
            .owner
            .provider
            .capacity(),
        0
    );
}

#[tokio::test]
async fn cache_bytes_entries_and_retained_metadata_are_bounded() {
    let inner = inner();
    let before = inner.lock().unwrap().health;
    let large = "x".repeat(512 * 1024);
    for number in 0..20 {
        let id = format!("large-{number}");
        cache::record(&inner, &request(&id), &mut response(&id, &large), before).unwrap();
    }
    assert!(inner.lock().unwrap().bytes <= VALUE_BYTES);
    for number in 0..520 {
        let id = format!("small-{number}");
        cache::record(&inner, &request(&id), &mut response(&id, "v"), before).unwrap();
    }
    let state = inner.lock().unwrap();
    assert!(state.values.len() <= VALUES);
    assert!(state.bytes <= VALUE_BYTES);
    assert!(
        state
            .secrets
            .values()
            .all(|entry| entry.metadata.as_ref().unwrap().value.capacity() == 0)
    );
}
#[tokio::test]
async fn last_source_handle_aborts_workers_without_retaining_secret_state() {
    let source = WatchedIssuer::new(client());
    let weak = Arc::downgrade(&source.inner);
    let clone = source.clone();
    drop(source);
    assert!(weak.upgrade().is_some());
    drop(clone);
    tokio::time::timeout(Duration::from_secs(1), async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
