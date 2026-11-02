// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::minter::RecoveryAction;
use tonic::Code;

fn checkpoint() -> GrantCheckpoint {
    GrantCheckpoint {
        identity: GrantIdentity {
            id: "grant-id".to_string(),
            authorization_epoch: "epoch".to_string(),
            owner: SecretOwner {
                workspace: "workspace".to_string(),
                provider_id: "provider-id".to_string(),
                credential_key: "ACCESS_TOKEN".to_string(),
            },
        },
        status: "configured".to_string(),
        completed_attempt: None,
        schedule: GrantSchedule {
            next_refresh_at_ms: 0,
            recovery_action: None,
            rotation_requested: false,
            deleting: false,
            pending_cleanup: false,
        },
    }
}

#[test]
fn changed_identity_or_owner_is_fenced_before_completed_mint_coalescing() {
    let observed = checkpoint();
    for field in 0..5 {
        let mut live = observed.clone();
        match field {
            0 => live.identity.id = "replacement-grant".to_string(),
            1 => live.identity.authorization_epoch = "reauthorized".to_string(),
            2 => live.identity.owner.workspace = "different-workspace".to_string(),
            3 => live.identity.owner.provider_id = "replacement-provider".to_string(),
            _ => live.identity.owner.credential_key = "OTHER_TOKEN".to_string(),
        }
        live.status = "refreshed".to_string();
        live.completed_attempt = Some("completed-attempt".to_string());
        assert_eq!(live.admit(&observed).unwrap_err().code(), Code::Aborted);
    }
}

#[test]
fn missing_identity_never_authorizes_a_mint_or_coalesces() {
    for live_invalid in [false, true] {
        for empty_epoch in [false, true] {
            let mut observed = checkpoint();
            let mut live = observed.clone();
            let invalid = if live_invalid {
                &mut live
            } else {
                &mut observed
            };
            if empty_epoch {
                invalid.identity.authorization_epoch.clear();
            } else {
                invalid.identity.id.clear();
            }
            assert_eq!(
                live.admit(&observed).unwrap_err().code(),
                Code::FailedPrecondition
            );
        }
    }
}

#[test]
fn deleting_grants_do_not_coalesce_or_admit_explicit_rotations() {
    let observed = checkpoint();
    let mut live = observed.clone();
    live.status = "refreshed".to_string();
    live.completed_attempt = Some("completed".to_string());
    live.schedule.deleting = true;
    live.schedule.rotation_requested = true;
    assert_eq!(
        live.admit(&observed).unwrap_err().message(),
        "provider refresh is being deleted"
    );
    for trigger in [RefreshTrigger::Automatic, RefreshTrigger::ExplicitRotation] {
        assert!(live.ensure_mintable(trigger, 100).is_err());
    }
}

#[test]
fn only_a_new_nonempty_completed_receipt_can_coalesce() {
    for status in [
        "configured",
        "refreshed",
        "refresh_in_progress",
        "refresh_committing",
        "error",
        "rotation_requested",
    ] {
        for before in [None, Some(""), Some("old"), Some("new")] {
            for after in [None, Some(""), Some("old"), Some("new")] {
                let mut observed = checkpoint();
                observed.completed_attempt = before.map(str::to_string);
                let mut live = observed.clone();
                live.status = status.to_string();
                live.completed_attempt = after.map(str::to_string);
                let expected = if status == "refreshed"
                    && after.is_some_and(|receipt| !receipt.is_empty())
                    && after != before
                {
                    GrantAdmission::Current
                } else {
                    GrantAdmission::Prepare
                };
                assert_eq!(
                    live.admit(&observed).unwrap(),
                    expected,
                    "{status}, {before:?}, {after:?}"
                );
            }
        }
    }
}

#[test]
fn neither_trigger_can_replay_an_uncertain_exchange() {
    for status in ["refresh_in_progress", "refresh_committing"] {
        let mut live = checkpoint();
        live.status = status.to_string();
        // A prior successful mint is not a receipt for the uncertain attempt.
        live.completed_attempt = Some("previous-completed".to_string());
        for trigger in [RefreshTrigger::Automatic, RefreshTrigger::ExplicitRotation] {
            for now in [0, i64::MAX] {
                let error = live.ensure_mintable(trigger, now).unwrap_err();
                assert_eq!(error.code(), Code::FailedPrecondition);
                assert!(error.message().contains("uncertain outcome"));
            }
        }
    }
}

#[test]
fn automatic_admission_rechecks_the_live_retry_schedule() {
    let observed = checkpoint();
    for action in [
        RecoveryAction::Retry,
        RecoveryAction::FixConfiguration,
        RecoveryAction::Investigate,
        RecoveryAction::Reauthorize,
    ] {
        let mut live = observed.clone();
        live.schedule.recovery_action = Some(action);
        live.schedule.next_refresh_at_ms = 101;
        assert_eq!(live.admit(&observed).unwrap(), GrantAdmission::Prepare);
        let error = live
            .ensure_mintable(RefreshTrigger::Automatic, 100)
            .unwrap_err();
        assert_eq!(
            error.code(),
            if action == RecoveryAction::Reauthorize {
                Code::FailedPrecondition
            } else {
                Code::Unavailable
            }
        );
        assert_eq!(
            live.ensure_mintable(RefreshTrigger::Automatic, 101).is_ok(),
            action != RecoveryAction::Reauthorize
        );
        live.ensure_mintable(RefreshTrigger::ExplicitRotation, 100)
            .unwrap();
    }
}

#[test]
fn healthy_on_demand_refresh_does_not_require_the_sweep_deadline() {
    let mut live = checkpoint();
    live.schedule.next_refresh_at_ms = i64::MAX;
    live.ensure_mintable(RefreshTrigger::Automatic, 1).unwrap();
}
