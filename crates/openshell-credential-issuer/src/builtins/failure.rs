// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::minter::{MintFailure, RecoveryAction, RetrySchedule};
use tonic::{Code, Status};
impl MintFailure {
    pub(crate) fn retryable(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: RecoveryAction::Retry,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RetrySchedule::Short,
        }
    }

    pub(crate) fn investigate(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: RecoveryAction::Investigate,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RetrySchedule::Short,
        }
    }

    pub(crate) fn reauthorize(
        status: Status,
        failure_code: &'static str,
        provider_error_subtype: Option<&'static str>,
    ) -> Self {
        Self {
            status,
            recovery_action: RecoveryAction::Reauthorize,
            failure_code,
            provider_error_subtype,
            retry_schedule: RetrySchedule::Parked,
        }
    }

    pub(crate) fn fix_configuration(status: Status, failure_code: &'static str) -> Self {
        Self {
            status,
            recovery_action: RecoveryAction::FixConfiguration,
            failure_code,
            provider_error_subtype: None,
            retry_schedule: RetrySchedule::Configuration,
        }
    }

    pub(crate) fn fix_configuration_with_subtype(
        status: Status,
        failure_code: &'static str,
        provider_error_subtype: &'static str,
    ) -> Self {
        Self {
            status,
            recovery_action: RecoveryAction::FixConfiguration,
            failure_code,
            provider_error_subtype: Some(provider_error_subtype),
            retry_schedule: RetrySchedule::Configuration,
        }
    }
}

impl From<Status> for MintFailure {
    fn from(status: Status) -> Self {
        match status.code() {
            Code::InvalidArgument
            | Code::FailedPrecondition
            | Code::PermissionDenied
            | Code::Unauthenticated => {
                Self::fix_configuration(status, "refresh_configuration_invalid")
            }
            Code::Unavailable
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal => Self::retryable(status, "refresh_failed"),
            _ => Self::investigate(status, "refresh_failed"),
        }
    }
}
