// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug)]
struct ScriptedResolver(Vec<ResolvedCredential>);

#[async_trait]
impl CredentialDriver for ScriptedResolver {
    async fn store_credential(
        &self,
        _request: StoreCredentialRequest,
    ) -> Result<CredentialHandle, Status> {
        Err(Status::unimplemented("resolve-only test driver"))
    }

    async fn delete_credential(&self, _request: DeleteCredentialRequest) -> Result<(), Status> {
        Err(Status::unimplemented("resolve-only test driver"))
    }

    async fn resolve_credentials(
        &self,
        requests: Vec<ResolveCredentialRequest>,
    ) -> Result<Vec<ResolvedCredential>, Status> {
        assert_eq!(
            requests.len(),
            2,
            "internal resolution must batch by driver"
        );
        for request in requests {
            assert_eq!(request.provider, "internal-owner");
            assert_eq!(request.workspace, "test-workspace");
            assert_eq!(request.provider_id, "test-owner-id");
            assert_eq!(request.credential_key, request.request_id);
            assert_eq!(request.handle.unwrap().driver, "test-static");
        }
        Ok(self.0.clone())
    }
}

fn resolved(key: &str) -> ResolvedCredential {
    ResolvedCredential {
        request_id: key.to_string(),
        value: format!("value-{key}"),
        expiration_time: None,
    }
}

#[tokio::test]
async fn internal_resolution_validates_batched_responses_and_forwards_ownership() {
    let owner = InternalSecretOwner {
        kind: openshell_credential_issuer::SecretOwnerKind::Sandbox,
        name: "internal-owner",
        workspace: "test-workspace",
        id: "test-owner-id",
    };
    let handles = ["first", "second"]
        .into_iter()
        .map(|key| {
            (
                key.to_string(),
                CredentialHandle {
                    driver: "test-static".to_string(),
                    handle: format!("handle-{key}"),
                    ..Default::default()
                },
            )
        })
        .collect();
    let cases = [
        (vec![resolved("second"), resolved("first")], true),
        (vec![resolved("first")], false),
        (vec![resolved("first"), resolved("first")], false),
        (vec![resolved("first"), resolved("unknown")], false),
        (vec![resolved("first"), resolved("")], false),
    ];
    for (responses, valid) in cases {
        let resolver: Arc<dyn CredentialDriver> = Arc::new(ScriptedResolver(responses));
        let internal = InternalSecretStore {
            issuer: None,
            registry: CredentialDriverRegistry::from_config(
                &Config::new(None).with_credential_drivers(["test-static"]),
            )
            .unwrap(),
            drivers: BTreeMap::from([("test-static".to_string(), resolver)]),
            _driver_processes: Vec::new(),
        };
        let result = internal.resolve(owner, &handles).await;
        if valid {
            assert_eq!(
                result.unwrap(),
                HashMap::from([
                    ("first".to_string(), "value-first".to_string()),
                    ("second".to_string(), "value-second".to_string()),
                ])
            );
        } else {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
        }
    }
}
