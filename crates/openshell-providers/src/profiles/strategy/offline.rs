// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::super::{ProfileValidationDiagnostic, ProviderTypeProfile, validate_profile_set_inner};
use super::custom_strategy_name_is_valid;

/// Check authored structure without contacting an issuer.
///
/// Custom declarations always retain an error requiring catalog validation:
/// structural success is not evidence that an issuer registered the strategy or
/// its output bundle. Existing offline callers can continue using
/// `validate_profile_set`; this form additionally reports structural diagnostics
/// for custom declarations.
#[must_use]
pub fn validate_profile_set_structure(
    profiles: &[(String, ProviderTypeProfile)],
) -> Vec<ProfileValidationDiagnostic> {
    let mut diagnostics = validate_profile_set_inner(profiles, true);
    for (source, profile) in profiles {
        if profile
            .credentials
            .iter()
            .filter_map(|credential| credential.refresh.as_ref())
            .any(|refresh| custom_strategy_name_is_valid(&refresh.strategy_name))
        {
            diagnostics.push(ProfileValidationDiagnostic::error(
                source, &profile.id, "credentials.refresh.strategy_name",
                "custom refresh structure requires validation against the selected issuer catalog before use",
            ));
        }
    }
    diagnostics
}
