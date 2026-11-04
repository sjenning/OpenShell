// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{
    ProviderCredentialRefreshStrategy, provider_refresh_strategy_from_yaml,
    provider_refresh_strategy_to_yaml,
};

/// Resolve compatible enum and exact-name strategy selectors.
///
/// Contradictory selectors fail closed. Names are registry identities, not YAML
/// aliases. This legacy enum resolver deliberately cannot approve custom names;
/// use catalog-aware profile validation for registered custom strategies.
pub fn resolve_refresh_strategy(
    strategy: i32,
    strategy_name: &str,
) -> Result<ProviderCredentialRefreshStrategy, String> {
    let legacy = ProviderCredentialRefreshStrategy::try_from(strategy)
        .map_err(|_| "unknown refresh strategy enum value".to_string())?;
    if strategy_name.is_empty() {
        return Ok(legacy);
    }
    let named = provider_refresh_strategy_from_yaml(strategy_name)
        .filter(|strategy| *strategy != ProviderCredentialRefreshStrategy::Unspecified)
        .filter(|strategy| provider_refresh_strategy_to_yaml(*strategy) == strategy_name)
        .ok_or_else(|| "refresh strategy name is not registered".to_string())?;
    if legacy != ProviderCredentialRefreshStrategy::Unspecified && legacy != named {
        return Err("refresh strategy enum and strategy_name disagree".to_string());
    }
    Ok(named)
}

mod catalog;
mod offline;
pub use catalog::{
    bind_profile_refresh_strategies, custom_strategy_name_is_valid, refresh_output_bindings,
    validate_profile_set_with_strategies,
};
pub use offline::validate_profile_set_structure;

#[cfg(test)]
mod catalog_tests;
#[cfg(test)]
mod profile_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_only_name_only_and_matching_pairs_resolve_identically() {
        for strategy in [
            ProviderCredentialRefreshStrategy::Static,
            ProviderCredentialRefreshStrategy::External,
            ProviderCredentialRefreshStrategy::Oauth2RefreshToken,
            ProviderCredentialRefreshStrategy::Oauth2ClientCredentials,
            ProviderCredentialRefreshStrategy::GoogleServiceAccountJwt,
            ProviderCredentialRefreshStrategy::AwsStsAssumeRole,
        ] {
            let name = provider_refresh_strategy_to_yaml(strategy);
            assert_eq!(
                resolve_refresh_strategy(strategy as i32, "").unwrap(),
                strategy
            );
            assert_eq!(resolve_refresh_strategy(0, name).unwrap(), strategy);
            assert_eq!(
                resolve_refresh_strategy(strategy as i32, name).unwrap(),
                strategy
            );
        }
        assert_eq!(
            resolve_refresh_strategy(0, "").unwrap(),
            ProviderCredentialRefreshStrategy::Unspecified
        );
    }

    #[test]
    fn contradictory_or_unknown_enum_selectors_are_never_overridden() {
        assert!(resolve_refresh_strategy(1, "oauth2_refresh_token").is_err());
        assert!(resolve_refresh_strategy(i32::MAX, "oauth2_refresh_token").is_err());
        assert!(resolve_refresh_strategy(i32::MAX, "").is_err());
    }

    #[test]
    fn names_are_exact_and_unregistered_custom_minters_fail_closed() {
        for name in [
            "OAuth2_Refresh_Token",
            " oauth2_refresh_token",
            "oauth2-refresh-token",
            "unspecified",
            "custom:acme",
            "other",
        ] {
            assert!(resolve_refresh_strategy(0, name).is_err(), "{name}");
        }
    }
}
