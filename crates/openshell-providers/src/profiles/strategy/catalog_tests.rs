// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::super::*;
use openshell_core::proto::credentials::minter::v1::{MaterialDescriptor, StrategyDescriptor};

fn profile() -> ProviderTypeProfile {
    parse_profile_yaml(
        r"
id: company
display_name: Company
credentials:
  - name: token
    env_vars: [COMPANY_TOKEN]
    required: true
    refresh:
      strategy_name: custom:company-sts
      refresh_before_seconds: 12
      material:
        - name: seed
          required: true
          secret: true
      additional_outputs:
        - output: auxiliary
          credential: auxiliary
  - name: auxiliary
    env_vars: [COMPANY_AUXILIARY]
    required: true
",
    )
    .unwrap()
}
fn descriptor() -> StrategyDescriptor {
    StrategyDescriptor {
        name: "custom:company-sts".into(),
        secret_material: vec![MaterialDescriptor {
            name: "seed".into(),
            required: true,
        }],
        // The primary deliberately follows the additional output.
        outputs: vec!["auxiliary".into(), "token".into()],
        ..Default::default()
    }
}

#[test]
fn registered_custom_profiles_are_runtime_eligible_only_after_catalog_binding() {
    let mut profiles = vec![("company.yaml".into(), profile())];
    assert!(!profiles[0].1.allows_empty_provider_credentials());
    assert!(!validate_profile_set(&profiles).is_empty());
    assert!(!validate_profile_set_with_strategies(&profiles, &[]).is_empty());
    assert!(bind_profile_refresh_strategies(&mut profiles, &[descriptor()]).is_empty());
    assert!(profiles[0].1.allows_empty_provider_credentials());
    assert!(profiles[0].1.allows_runtime_provider_credentials());
    assert!(profiles[0].1.required_static_credentials().is_empty());
    let outputs = refresh_output_bindings(&profiles[0].1, "COMPANY_TOKEN", &descriptor()).unwrap();
    assert_eq!(outputs["token"], "COMPANY_TOKEN");
    assert_eq!(outputs["auxiliary"], "COMPANY_AUXILIARY");
    let decoded = ProviderTypeProfile::from_proto(&profiles[0].1.to_proto());
    assert!(!decoded.allows_empty_provider_credentials());
    let decoded = parse_profile_yaml(&profile_to_yaml(&profiles[0].1).unwrap()).unwrap();
    assert!(!decoded.allows_empty_provider_credentials());
    assert!(!bind_profile_refresh_strategies(&mut profiles, &[]).is_empty());
    assert!(!profiles[0].1.allows_empty_provider_credentials());
}

#[test]
fn custom_profile_output_ambiguity_unknown_outputs_and_duplicate_targets_fail_closed() {
    for change in 0..5 {
        let mut profile = profile();
        let refresh = profile.credentials[0].refresh.as_mut().unwrap();
        match change {
            0 => refresh.additional_outputs.clear(),
            1 => refresh.additional_outputs[0].output = "absent".into(),
            2 => refresh
                .additional_outputs
                .push(refresh.additional_outputs[0].clone()),
            3 => refresh.additional_outputs[0].credential = "token".into(),
            _ => profile.credentials[0].env_vars.push("ALIAS".into()),
        }
        let diagnostics =
            validate_profile_set_with_strategies(&[(String::new(), profile)], &[descriptor()]);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.field.contains("additional_outputs")),
            "{change}: {diagnostics:?}"
        );
    }
}

#[test]
fn profile_material_classification_and_stable_placeholders_cannot_override_the_descriptor() {
    for change in 0..3 {
        let mut profile = profile();
        match change {
            0 => profile.credentials[0].refresh.as_mut().unwrap().material[0].secret = false,
            1 => {
                profile.credentials[0].refresh.as_mut().unwrap().material[0].name = "absent".into();
            }
            _ => profile.credentials[1].stable_placeholder = true,
        }
        assert!(
            !validate_profile_set_with_strategies(&[(String::new(), profile)], &[descriptor()])
                .is_empty()
        );
    }
}

#[test]
fn selected_catalog_must_also_register_builtin_minters() {
    let mut profile = profile();
    let refresh = profile.credentials[0].refresh.as_mut().unwrap();
    refresh.strategy_name = "oauth2_client_credentials".into();
    refresh.additional_outputs.clear();
    refresh.material.clear();
    let profiles = [(String::new(), profile)];
    assert!(validate_profile_set(&profiles).is_empty());
    assert!(!validate_profile_set_with_strategies(&profiles, &[]).is_empty());
    let descriptor = StrategyDescriptor {
        name: "oauth2_client_credentials".into(),
        outputs: vec!["access_token".into()],
        ..Default::default()
    };
    assert!(validate_profile_set_with_strategies(&profiles, &[descriptor]).is_empty());
}

#[test]
fn custom_selectors_are_bounded_exact_and_never_override_enum_or_wire_errors() {
    for name in [
        "custom:",
        " custom:company-sts",
        "custom:COMPANY",
        "custom:company/sts",
    ] {
        assert!(!custom_strategy_name_is_valid(name));
    }
    let mut profile = profile();
    profile.credentials[0].refresh.as_mut().unwrap().strategy =
        ProviderCredentialRefreshStrategy::Static;
    assert!(
        !validate_profile_set_with_strategies(&[(String::new(), profile.clone())], &[descriptor()])
            .is_empty()
    );
    let mut proto = profile.to_proto();
    let refresh = proto.credentials[0].refresh.as_mut().unwrap();
    refresh.strategy = i32::MAX;
    refresh.strategy_name = "custom:company-sts".into();
    assert!(
        !validate_profile_set_with_strategies(
            &[(String::new(), ProviderTypeProfile::from_proto(&proto))],
            &[descriptor()]
        )
        .is_empty()
    );
}

#[test]
fn offline_custom_structure_checks_never_approve_unregistered_strategies() {
    let mut profile = profile();
    profile.credentials[0]
        .refresh
        .as_mut()
        .unwrap()
        .additional_outputs[0]
        .credential = "absent".into();
    let diagnostics = validate_profile_set_structure(&[(String::new(), profile)]);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unknown credential"))
    );
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic.message.contains("selected issuer catalog") && diagnostic.severity == "error"
    }));
}

#[test]
fn distinct_profile_refreshes_cannot_claim_the_same_additional_credential() {
    let mut profile = profile();
    let mut second = profile.credentials[0].clone();
    second.name = "second".into();
    second.env_vars = vec!["SECOND_TOKEN".into()];
    profile.credentials.push(second);
    let diagnostics =
        validate_profile_set_with_strategies(&[(String::new(), profile)], &[descriptor()]);
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("multiple grants"))
    );
}

#[test]
fn issuer_output_bundles_validate_environment_key_syntax_and_bounds_at_profile_validation() {
    for primary in [false, true] {
        for value in ["INVALID-KEY".to_string(), "X".repeat(129)] {
            let mut profile = profile();
            profile.credentials[usize::from(!primary)].env_vars = vec![value];
            let diagnostics =
                bind_profile_refresh_strategies(&mut [(String::new(), profile)], &[descriptor()]);
            assert!(
                diagnostics
                    .iter()
                    .any(|diagnostic| diagnostic.message.contains("valid environment names"))
            );
        }
    }
    let mut oversized = descriptor();
    oversized.outputs = (0..65).map(|index| format!("output_{index}")).collect();
    assert!(
        !validate_profile_set_with_strategies(&[(String::new(), profile())], &[oversized])
            .is_empty()
    );
}

#[test]
fn serialized_profile_fields_cannot_forge_issuer_registration_evidence() {
    let mut json = serde_json::to_value(profile()).unwrap();
    json["credentials"][0]["refresh"]["registered_strategy_name"] = "custom:company-sts".into();
    let forged: ProviderTypeProfile = serde_json::from_value(json).unwrap();
    assert!(!forged.allows_empty_provider_credentials());
    assert!(!forged.allows_runtime_provider_credentials());
    assert!(!validate_profile_set_with_strategies(&[(String::new(), forged)], &[]).is_empty());
}
