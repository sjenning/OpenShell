// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::*;

#[test]
fn name_only_profiles_round_trip_and_export_a_compatible_enum() {
    let refresh: CredentialRefreshProfile =
        serde_json::from_str(r#"{"strategy_name":"oauth2_refresh_token"}"#).unwrap();
    assert!(refresh.is_gateway_mintable());
    let proto = credential_refresh_to_proto(&refresh);
    assert_eq!(
        proto.strategy,
        ProviderCredentialRefreshStrategy::Oauth2RefreshToken as i32
    );
    assert_eq!(proto.strategy_name, "oauth2_refresh_token");
    let decoded = credential_refresh_from_proto(&proto);
    assert_eq!(decoded.effective_strategy(), refresh.effective_strategy());
    assert_eq!(decoded.strategy_name, refresh.strategy_name);
    // Canonicalizing the enum for older clients must not make an unchanged
    // authored profile look modified on every reconciliation.
    assert_eq!(decoded, refresh);
    let json = serde_json::to_string(&refresh).unwrap();
    assert!(!json.contains("unspecified"));
    assert_eq!(
        serde_json::from_str::<CredentialRefreshProfile>(&json).unwrap(),
        refresh
    );
    let yaml = serde_yml::to_string(&refresh).unwrap();
    assert_eq!(
        serde_yml::from_str::<CredentialRefreshProfile>(&yaml).unwrap(),
        refresh
    );
}

#[test]
fn named_profiles_validate_and_remain_eligible_for_runtime_and_adc_bootstrap() {
    let profile = parse_profile_yaml(
        r"
id: named-oauth
display_name: Named OAuth
credentials:
  - name: token
    env_vars: [ACCESS_TOKEN]
    required: true
    auth_style: bearer
    header_name: Authorization
    refresh:
      strategy_name: oauth2_refresh_token
      token_url: https://example.test/token
      material:
        - name: client_id
          required: true
        - name: client_secret
          secret: true
        - name: refresh_token
          required: true
          secret: true
",
    )
    .unwrap();
    let diagnostics = validate_profile_set(&[("test".to_string(), profile.clone())]);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert!(profile.allows_empty_provider_credentials());
    assert!(profile.adc_credential().is_some());
    let decoded = ProviderTypeProfile::from_proto(&profile.to_proto());
    assert!(decoded.allows_empty_provider_credentials());
    assert!(decoded.adc_credential().is_some());
}

#[test]
fn unknown_wire_enums_cannot_be_reinterpreted_as_name_only_selectors() {
    let refresh = credential_refresh_from_proto(&ProviderCredentialRefresh {
        strategy: i32::MAX,
        strategy_name: "oauth2_refresh_token".to_string(),
        ..Default::default()
    });
    assert!(!refresh.is_gateway_mintable());
    assert_eq!(
        refresh.effective_strategy().unwrap(),
        ProviderCredentialRefreshStrategy::Unspecified
    );
}

#[test]
fn named_aws_profiles_still_require_all_outputs_and_the_canonical_primary_key() {
    let profile = parse_profile_yaml(
        r"
id: named-aws
display_name: Named AWS
credentials:
  - name: access
    env_vars: [WRONG_KEY]
    refresh:
      strategy_name: aws_sts_assume_role
",
    )
    .unwrap();
    let diagnostics = validate_profile_set(&[("test".to_string(), profile)]);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("secret_access_key"))
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("session_token"))
    );
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("AWS_ACCESS_KEY_ID"))
    );
}

#[test]
fn contradictory_profile_selectors_and_custom_names_are_rejected() {
    for selector in [
        "strategy: static\n      strategy_name: oauth2_refresh_token",
        "strategy_name: custom:acme",
    ] {
        let profile = parse_profile_yaml(&format!("id: rejected\ndisplay_name: Rejected\ncredentials:\n  - name: token\n    env_vars: [TOKEN]\n    refresh:\n      {selector}\n")).unwrap();
        assert!(
            !profile.credentials[0]
                .refresh
                .as_ref()
                .unwrap()
                .is_gateway_mintable()
        );
        assert!(
            validate_profile_set(&[("test".to_string(), profile)])
                .iter()
                .any(|d| d.field == "credentials.refresh.strategy_name")
        );
    }
}
