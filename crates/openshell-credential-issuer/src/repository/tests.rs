// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::auth::test_scope;
use tonic::Code;

mod postgres;

#[tokio::test]
async fn list_pages_are_bounded_and_do_not_repeat_keys() {
    let repo = Repository::open("sqlite::memory:")
        .await
        .unwrap()
        .for_gateway(&test_scope("a"));
    repo.commit(
        &[
            put("a", None, "1"),
            put("b", None, "2"),
            put("c", None, "3"),
        ],
        &[],
    )
    .await
    .unwrap();
    let first = repo.list("reference", None, 2).await.unwrap();
    assert_eq!(
        first
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
    let second = repo.list("reference", Some("b"), 2).await.unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].0, "c");
    assert_eq!(
        repo.list("reference", None, 0).await.unwrap_err().code(),
        Code::InvalidArgument
    );
}

#[tokio::test]
async fn unsupported_schema_is_rejected_without_overwriting_it() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("issuer.db").display()
    );
    let repository = Repository::open(&url).await.unwrap();
    sqlx::query("UPDATE issuer_schema SET version=2 WHERE id=1")
        .execute(&repository.pool)
        .await
        .unwrap();
    assert_eq!(
        Repository::open(&url).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    let row = sqlx::query("SELECT version FROM issuer_schema WHERE id=1")
        .fetch_one(&repository.pool)
        .await
        .unwrap();
    assert_eq!(row.try_get::<i32, _>("version").unwrap(), 2);
}

fn put(key: &str, expected: Option<u64>, value: &str) -> Mutation {
    Mutation::Put {
        kind: "reference".to_string(),
        key: key.to_string(),
        expected,
        payload: value.as_bytes().to_vec(),
    }
}
fn change(key: &str, version: u64) -> Change {
    Change {
        kind: "secret".to_string(),
        key: key.to_string(),
        version,
        deleted: false,
    }
}

#[tokio::test]
async fn scoped_objects_and_events_cannot_cross_gateway_namespaces() {
    let repository = Repository::open("sqlite::memory:").await.unwrap();
    let a = repository.for_gateway(&test_scope("a"));
    let b = repository.for_gateway(&test_scope("b"));
    let receipt = a
        .commit(
            &[put("same-ref", None, "private-a")],
            &[change("same-ref", 1)],
        )
        .await
        .unwrap();
    assert_eq!(receipt.last_sequence, Some(1));
    assert!(b.load("reference", "same-ref").await.unwrap().is_none());
    assert!(b.events_after(0, 10).await.unwrap().is_empty());
    assert!(b.list("reference", None, 10).await.unwrap().is_empty());
    b.commit(
        &[put("same-ref", None, "private-b")],
        &[change("same-ref", 1)],
    )
    .await
    .unwrap();
    assert_eq!(
        a.load("reference", "same-ref")
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"private-a"
    );
    assert_eq!(
        b.load("reference", "same-ref")
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"private-b"
    );
    assert!(
        !format!(
            "{:?}",
            a.load("reference", "same-ref").await.unwrap().unwrap()
        )
        .contains("private-a")
    );
}

#[tokio::test]
async fn stale_batch_member_rolls_back_all_outputs_and_change_sequences() {
    let repo = Repository::open("sqlite::memory:")
        .await
        .unwrap()
        .for_gateway(&test_scope("a"));
    repo.commit(
        &[put("a", None, "old-a"), put("b", None, "old-b")],
        &[change("a", 1), change("b", 1)],
    )
    .await
    .unwrap();
    let before = repo.events_after(0, 10).await.unwrap();
    let error = repo
        .commit(
            &[put("a", Some(1), "new-a"), put("b", Some(99), "new-b")],
            &[change("a", 2), change("b", 2)],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
    assert_eq!(
        repo.load("reference", "a").await.unwrap().unwrap().payload,
        b"old-a"
    );
    assert_eq!(repo.events_after(0, 10).await.unwrap(), before);
    let receipt = repo
        .commit(
            &[put("a", Some(1), "new-a"), put("b", Some(1), "new-b")],
            &[change("a", 2), change("b", 2)],
        )
        .await
        .unwrap();
    assert_eq!(receipt.last_sequence, Some(4));
    assert_eq!(repo.events_after(2, 1).await.unwrap()[0].sequence, 3);
    assert_eq!(repo.events_after(3, 10).await.unwrap()[0].change.key, "b");
}

#[tokio::test]
async fn revision_checks_do_not_mutate_and_failed_checks_fence_publication() {
    let repo = Repository::open("sqlite::memory:")
        .await
        .unwrap()
        .for_gateway(&test_scope("a"));
    repo.commit(
        &[
            put("owner", None, "owner-payload"),
            put("output", None, "old"),
        ],
        &[],
    )
    .await
    .unwrap();
    let check = Mutation::Check {
        kind: "reference".to_string(),
        key: "owner".to_string(),
        expected: 1,
    };
    let receipt = repo
        .commit(
            &[check.clone(), put("output", Some(1), "new")],
            &[change("output", 2)],
        )
        .await
        .unwrap();
    assert_eq!(
        receipt.revisions[&("reference".to_string(), "owner".to_string())],
        1
    );
    let owner = repo.load("reference", "owner").await.unwrap().unwrap();
    assert_eq!(owner.revision, 1);
    assert_eq!(owner.payload, b"owner-payload");
    repo.commit(&[put("owner", Some(1), "changed")], &[])
        .await
        .unwrap();
    assert_eq!(
        repo.commit(
            &[check, put("output", Some(2), "must-not-publish")],
            &[change("output", 3)]
        )
        .await
        .unwrap_err()
        .code(),
        Code::Aborted
    );
    assert_eq!(
        repo.load("reference", "output")
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"new"
    );
    assert_eq!(repo.events_after(0, 10).await.unwrap().len(), 1);
}

#[tokio::test]
async fn durable_rows_and_watch_cursors_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("issuer.db").display()
    );
    {
        let repository = Repository::open(&url).await.unwrap();
        let repo = repository.for_gateway(&test_scope("a"));
        repo.commit(
            &[put("reference", None, "persisted")],
            &[change("reference", u64::MAX)],
        )
        .await
        .unwrap();
    }
    let repository = Repository::open(&url).await.unwrap();
    let repo = repository.for_gateway(&test_scope("a"));
    assert_eq!(
        repo.load("reference", "reference")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    let event = repo.events_after(0, 10).await.unwrap().pop().unwrap();
    assert_eq!(event.sequence, 1);
    assert_eq!(event.change.version, u64::MAX);
    assert_eq!(
        repo.commit(
            &[put("reference", Some(1), "updated")],
            &[change("reference", 2)]
        )
        .await
        .unwrap()
        .last_sequence,
        Some(2)
    );
}

#[tokio::test]
async fn invalid_and_duplicate_mutations_never_change_state() {
    let repo = Repository::open("sqlite::memory:")
        .await
        .unwrap()
        .for_gateway(&test_scope("a"));
    for mutations in [
        vec![],
        vec![put("x", None, "one"), put("x", None, "two")],
        vec![put("", None, "empty-key")],
    ] {
        assert_eq!(
            repo.commit(&mutations, &[]).await.unwrap_err().code(),
            Code::InvalidArgument
        );
    }
    repo.commit(&[put("x", None, "one")], &[]).await.unwrap();
    assert_eq!(
        repo.commit(&[put("x", None, "two")], &[])
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        repo.commit(&[put("x", Some(u64::MAX), "overflow")], &[])
            .await
            .unwrap_err()
            .code(),
        Code::OutOfRange
    );
    assert_eq!(
        repo.load("reference", "x").await.unwrap().unwrap().payload,
        b"one"
    );
}

#[tokio::test]
async fn deletion_is_revision_fenced_and_can_atomically_publish_a_tombstone_event() {
    let repo = Repository::open("sqlite::memory:")
        .await
        .unwrap()
        .for_gateway(&test_scope("a"));
    repo.commit(&[put("x", None, "old")], &[]).await.unwrap();
    let mut event = change("x", 2);
    event.deleted = true;
    assert!(
        repo.commit(
            &[Mutation::Delete {
                kind: "reference".to_string(),
                key: "x".to_string(),
                expected: 2
            }],
            &[event.clone()]
        )
        .await
        .is_err()
    );
    assert!(repo.load("reference", "x").await.unwrap().is_some());
    repo.commit(
        &[Mutation::Delete {
            kind: "reference".to_string(),
            key: "x".to_string(),
            expected: 1,
        }],
        &[event.clone()],
    )
    .await
    .unwrap();
    assert!(repo.load("reference", "x").await.unwrap().is_none());
    assert_eq!(repo.events_after(0, 10).await.unwrap()[0].change, event);
}
