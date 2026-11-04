// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//! Profile validation against the selected issuer's authenticated catalog.
use super::super::{
    ProfileValidationDiagnostic, ProviderCredentialRefreshStrategy, ProviderTypeProfile,
    is_gateway_mintable_strategy, provider_refresh_strategy_to_yaml, validate_profile_set_inner,
};
use openshell_core::proto::credentials::minter::v1::StrategyDescriptor;
use std::collections::{BTreeMap, HashSet};

#[must_use]
pub fn custom_strategy_name_is_valid(name: &str) -> bool {
    name.len() <= 128 && name.strip_prefix("custom:").is_some_and(valid_id)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn valid_output_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Resolve the fixed output bundle without relying on descriptor order.
///
/// The sole output not explicitly mapped by `additional_outputs` is the primary.
pub fn refresh_output_bindings(
    profile: &ProviderTypeProfile,
    credential_key: &str,
    descriptor: &StrategyDescriptor,
) -> Result<BTreeMap<String, String>, String> {
    if !valid_output_key(credential_key) {
        return Err(
            "refresh output keys must be valid environment names of at most 128 bytes".into(),
        );
    }
    let credential = profile
        .credentials
        .iter()
        .find(|credential| {
            credential.name == credential_key
                || credential.env_vars.iter().any(|key| key == credential_key)
        })
        .ok_or("refresh primary credential is not declared by the profile")?;
    let refresh = credential
        .refresh
        .as_ref()
        .ok_or("profile does not declare refresh")?;
    if custom_strategy_name_is_valid(&descriptor.name)
        && (credential.env_vars.len() != 1 || credential.env_vars[0] != credential_key)
    {
        return Err(
            "custom refresh primary credential must declare exactly one environment key".into(),
        );
    }
    let declared: HashSet<_> = descriptor.outputs.iter().map(String::as_str).collect();
    if declared.is_empty()
        || declared.len() > 64
        || declared.len() != descriptor.outputs.len()
        || descriptor.outputs.iter().any(|output| !valid_id(output))
    {
        return Err("issuer strategy has an invalid output descriptor".into());
    }
    let mut outputs = BTreeMap::new();
    let mut keys = HashSet::from([credential_key.to_string()]);
    for output in &refresh.additional_outputs {
        if !declared.contains(output.output.as_str()) {
            return Err("profile maps an output not produced by the issuer strategy".into());
        }
        let sibling = profile
            .credentials
            .iter()
            .find(|candidate| candidate.name == output.credential)
            .ok_or("profile output references an unknown credential")?;
        let [key] = sibling.env_vars.as_slice() else {
            return Err(
                "refresh output credential must declare exactly one environment key".into(),
            );
        };
        if !valid_output_key(key) {
            return Err(
                "refresh output keys must be valid environment names of at most 128 bytes".into(),
            );
        }
        if sibling.refresh.is_some()
            || !keys.insert(key.clone())
            || outputs.insert(output.output.clone(), key.clone()).is_some()
        {
            return Err(
                "refresh output bindings must have distinct outputs and credential keys".into(),
            );
        }
    }
    let mut primary = descriptor
        .outputs
        .iter()
        .filter(|output| !outputs.contains_key(*output));
    let name = primary
        .next()
        .ok_or("profile does not leave an output for the primary credential")?;
    if primary.next().is_some() {
        return Err(
            "profile output mapping is ambiguous; map every additional issuer output".into(),
        );
    }
    if !custom_strategy_name_is_valid(&descriptor.name) {
        let expected = if descriptor.name == "aws_sts_assume_role" {
            "access_key_id"
        } else {
            "access_token"
        };
        if name != expected {
            return Err(
                "issuer builtin strategy descriptor has an incompatible primary output".into(),
            );
        }
    }
    outputs.insert(name.clone(), credential_key.into());
    Ok(outputs)
}

fn mark_registered(
    profiles: &mut [(String, ProviderTypeProfile)],
    strategies: &[StrategyDescriptor],
) {
    for (_, profile) in profiles {
        for credential in &mut profile.credentials {
            if let Some(refresh) = &mut credential.refresh {
                refresh.registered_strategy_name = (refresh.strategy
                    == ProviderCredentialRefreshStrategy::Unspecified
                    && custom_strategy_name_is_valid(&refresh.strategy_name)
                    && strategies
                        .iter()
                        .any(|descriptor| descriptor.name == refresh.strategy_name))
                .then(|| refresh.strategy_name.clone());
            }
        }
    }
}

/// Validate minter declarations against the selected issuer catalog.
///
/// Offline validation remains conservative. Only this catalog-aware path can
/// approve a custom strategy, and built-in minters must also exist in the
/// selected issuer (static/external strategies do not require a minter).
#[must_use]
pub fn validate_profile_set_with_strategies(
    profiles: &[(String, ProviderTypeProfile)],
    strategies: &[StrategyDescriptor],
) -> Vec<ProfileValidationDiagnostic> {
    let mut bound = profiles.to_vec();
    mark_registered(&mut bound, strategies);
    let mut diagnostics = validate_profile_set_inner(&bound, true);
    for (source, profile) in &bound {
        let mut claimed_keys = HashSet::new();
        for credential in &profile.credentials {
            let Some(refresh) = &credential.refresh else {
                continue;
            };
            let custom = refresh.strategy == ProviderCredentialRefreshStrategy::Unspecified
                && custom_strategy_name_is_valid(&refresh.strategy_name);
            let builtin = refresh
                .effective_strategy()
                .ok()
                .filter(|strategy| is_gateway_mintable_strategy(*strategy));
            if !custom && builtin.is_none() {
                continue;
            }
            let name = builtin.map_or(refresh.strategy_name.as_str(), |strategy| {
                provider_refresh_strategy_to_yaml(strategy)
            });
            let matches: Vec<_> = strategies
                .iter()
                .filter(|descriptor| descriptor.name == name)
                .collect();
            let error = |field: &str, message: &str| {
                ProfileValidationDiagnostic::error(source, &profile.id, field, message)
            };
            let [descriptor] = matches.as_slice() else {
                diagnostics.push(error(
                    "credentials.refresh.strategy_name",
                    "refresh strategy is unavailable or ambiguous in the selected issuer catalog",
                ));
                continue;
            };
            if custom {
                if descriptor
                    .config
                    .iter()
                    .chain(&descriptor.secret_material)
                    .any(|field| {
                        matches!(
                            field.name.as_str(),
                            "refresh_before_seconds" | "max_lifetime_seconds"
                        )
                    })
                {
                    diagnostics.push(error(
                        "credentials.refresh.material",
                        "custom issuer descriptor conflicts with gateway scheduling controls",
                    ));
                }
                for (field, present) in [
                    ("token_url", !refresh.token_url.is_empty()),
                    ("scope", !refresh.scopes.is_empty()),
                ] {
                    if present && !descriptor.config.iter().any(|item| item.name == field) {
                        diagnostics.push(error(
                            "credentials.refresh.material",
                            "custom profile defaults are not supported by the issuer descriptor",
                        ));
                    }
                }
            }
            // Material classification is an issuer contract, not a profile hint.
            for material in &refresh.material {
                let config = descriptor
                    .config
                    .iter()
                    .any(|field| field.name == material.name);
                let secret = descriptor
                    .secret_material
                    .iter()
                    .any(|field| field.name == material.name);
                if config == secret || material.secret != secret {
                    diagnostics.push(error("credentials.refresh.material", "profile material classification disagrees with the selected issuer descriptor"));
                }
            }
            let key = credential
                .env_vars
                .first()
                .map_or(credential.name.as_str(), String::as_str);
            match refresh_output_bindings(profile, key, descriptor) {
                Ok(outputs) => {
                    for key in outputs.into_values() {
                        if !claimed_keys.insert(key) {
                            diagnostics.push(error(
                                "credentials.refresh.additional_outputs",
                                "profile refresh output credential is produced by multiple grants",
                            ));
                        }
                    }
                }
                Err(message) => {
                    diagnostics.push(error("credentials.refresh.additional_outputs", &message));
                }
            }
        }
    }
    diagnostics
}

/// Authorize runtime eligibility only after complete catalog validation. The
/// evidence is local to this in-memory profile and cannot survive serialization.
pub fn bind_profile_refresh_strategies(
    profiles: &mut [(String, ProviderTypeProfile)],
    strategies: &[StrategyDescriptor],
) -> Vec<ProfileValidationDiagnostic> {
    let diagnostics = validate_profile_set_with_strategies(profiles, strategies);
    // Clear stale evidence even when revalidation fails.
    mark_registered(profiles, &[]);
    if !diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == "error")
    {
        mark_registered(profiles, strategies);
    }
    diagnostics
}
