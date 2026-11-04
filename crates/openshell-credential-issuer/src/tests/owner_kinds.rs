// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use crate::{SecretOwner, SecretOwnerKind};
use openshell_core::proto::credentials::store::v1 as wire;

#[test]
fn typed_owners_preserve_provider_storage_identity_and_separate_internal_kinds() {
    let legacy = wire::SecretOwner {
        workspace: "workspace".into(),
        provider_id: "object".into(),
        credential_key: "KEY".into(),
        provider: "display".into(),
        ..Default::default()
    };
    let provider = SecretOwner::from_wire(&legacy).unwrap();
    assert_eq!(
        serde_json::to_string(&provider).unwrap(),
        r#"{"workspace":"workspace","provider_id":"object","credential_key":"KEY"}"#
    );
    let typed = wire::SecretOwner {
        provider_id: String::new(),
        provider: String::new(),
        kind: Some(wire::secret_owner::Kind::ProviderOwner(
            wire::ProviderSecretOwner {
                provider_id: "object".into(),
            },
        )),
        ..legacy
    };
    assert_eq!(provider, SecretOwner::from_wire(&typed).unwrap());
    let sandbox = SecretOwner::from_wire(&wire::SecretOwner {
        kind: Some(wire::secret_owner::Kind::Sandbox(
            wire::SandboxSecretOwner {
                sandbox_id: "object".into(),
            },
        )),
        ..typed.clone()
    })
    .unwrap();
    let instance = SecretOwner::from_wire(&wire::SecretOwner {
        kind: Some(wire::secret_owner::Kind::SupervisorInstance(
            wire::SupervisorInstanceSecretOwner {
                instance_id: "object".into(),
            },
        )),
        ..typed.clone()
    })
    .unwrap();
    assert_eq!(sandbox.kind, SecretOwnerKind::Sandbox);
    assert_ne!(provider, sandbox);
    assert_ne!(instance, sandbox);
    let ambiguous = wire::SecretOwner {
        provider_id: "object".into(),
        ..typed
    };
    assert_eq!(
        SecretOwner::from_wire(&ambiguous).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}
