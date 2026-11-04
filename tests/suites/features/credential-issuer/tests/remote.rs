// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Run through `mise run e2e:credential-issuer[:kind]`. Missing fixture inputs
//! fail with setup instructions; this deployment lane never silently skips.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use openshell_core::proto::credentials::{minter::v1 as minter, store::v1 as store};
use openshell_extension_core::{ExtensionChannelConfig, ExtensionClientIdentity, connect_channel};
use testkit::sdk::raw::{AuthedGrpcClient, proto};
use testkit::{Context, Error, Poll, Sandbox, poll_until};
use tonic::{Code, Request};

const KEY: &str = "ISSUER_E2E_ACCESS_TOKEN";
const WAIT: Duration = Duration::from_secs(90);
const INTERVAL: Duration = Duration::from_millis(500);

fn required(key: &str) -> testkit::Result<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::msg(format!(
                "{key} is required: run mise run e2e:credential-issuer:kind or follow \
             tests/suites/features/credential-issuer/README.md; no deployment tests were skipped"
            ))
        })
}

fn rpc<T>(body: T) -> Request<T> {
    let mut request = Request::new(body);
    request.set_timeout(Duration::from_secs(15));
    request
}

fn scope() -> Option<proto::datamodel::v1::WorkspaceSelector> {
    Some(proto::workspace_selector("default"))
}

fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn status(error: tonic::Status) -> Error {
    // Never include remote messages or response bodies in test artifacts.
    Error::msg(format!("RPC failed with {:?}", error.code()))
}

async fn public_client() -> testkit::Result<AuthedGrpcClient> {
    let client = testkit::Gateway::from_env()?.connect().await?;
    client.raw_grpc_fresh().await.map_err(Error::from)
}

async fn export(client: &mut AuthedGrpcClient, provider: &str) -> testkit::Result<String> {
    let result = client
        .get_provider_credentials(rpc(proto::GetProviderCredentialsRequest {
            workspace_scope: scope(),
            name: provider.into(),
            credential_keys: vec![KEY.into()],
            minimum_remaining_lifetime: Some(prost_types::Duration {
                seconds: 1,
                nanos: 0,
            }),
        }))
        .await
        .map_err(status)?
        .into_inner();
    let credential = result
        .credentials
        .get(KEY)
        .ok_or_else(|| Error::msg("export omitted key"))?;
    testkit::ensure!(
        credential.value.starts_with("fixture-"),
        "export did not resolve the custom minter output"
    );
    testkit::ensure!(
        credential.expiration_time.is_some(),
        "export lost issuer-owned expiry"
    );
    Ok(credential.value.clone())
}

async fn rotate(client: &mut AuthedGrpcClient, provider: &str) -> testkit::Result {
    let result = client
        .rotate_provider_credential(rpc(proto::RotateProviderCredentialRequest {
            workspace_scope: scope(),
            provider: provider.into(),
            credential_key: KEY.into(),
            request_id: id(),
        }))
        .await
        .map_err(status)?
        .into_inner();
    let result = result
        .status
        .ok_or_else(|| Error::msg("rotate omitted status"))?;
    testkit::ensure!(
        result.status == "refreshed",
        "rotate did not report refreshed: {}",
        result.status
    );
    Ok(())
}

async fn configure(client: &mut AuthedGrpcClient, provider: &str) -> testkit::Result {
    client
        .configure_provider_refresh(rpc(proto::ConfigureProviderRefreshRequest {
            workspace_scope: scope(),
            provider: provider.into(),
            credential_key: KEY.into(),
            strategy_name: "custom:e2e".into(),
            material: HashMap::from([
                ("audience".into(), "resource".into()),
                ("seed".into(), "synthetic-e2e-seed".into()),
                ("refresh_before_seconds".into(), "10".into()),
                ("max_lifetime_seconds".into(), "3600".into()),
            ]),
            // Intentionally omit secret_material_keys: discovery must classify seed.
            request_id: id(),
            ..Default::default()
        }))
        .await
        .map_err(status)?;
    Ok(())
}

async fn scale_issuer(replicas: &str) -> testkit::Result {
    let kubeconfig = required("OPENSHELL_ISSUER_E2E_KUBECONFIG")?;
    let context = required("OPENSHELL_ISSUER_E2E_ISSUER_CONTEXT")?;
    let namespace = required("OPENSHELL_ISSUER_E2E_ISSUER_NAMESPACE")?;
    async fn kubectl(
        kubeconfig: &str,
        context: &str,
        namespace: &str,
        args: Vec<String>,
    ) -> testkit::Result {
        let output = tokio::process::Command::new("kubectl")
            .args([
                "--kubeconfig",
                kubeconfig,
                "--context",
                context,
                "--namespace",
                namespace,
                "--request-timeout=30s",
            ])
            .args(args)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(Error::from_display)?;
        testkit::ensure!(
            output.status.success(),
            "issuer fixture control failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    kubectl(
        &kubeconfig,
        &context,
        &namespace,
        vec![
            "scale".into(),
            "deployment/issuer".into(),
            format!("--replicas={replicas}"),
        ],
    )
    .await?;
    if replicas == "0" {
        kubectl(
            &kubeconfig,
            &context,
            &namespace,
            vec![
                "wait".into(),
                "pod".into(),
                "-l".into(),
                "app.kubernetes.io/instance=issuer".into(),
                "--for=delete".into(),
                "--timeout=90s".into(),
            ],
        )
        .await?;
    } else {
        kubectl(
            &kubeconfig,
            &context,
            &namespace,
            vec![
                "rollout".into(),
                "status".into(),
                "deployment/issuer".into(),
                "--timeout=180s".into(),
            ],
        )
        .await?;
    }
    Ok(())
}

async fn probe(sandbox: &Sandbox) -> testkit::Result<bool> {
    // The main process retains its original environment. Exec merely triggers
    // its child, and cannot mask delivery regressions with a newly issued handle.
    let output = sandbox
        .exec([
            "sh",
            "-ec",
            "rm -f /sandbox/probe-result; touch /sandbox/probe-trigger",
        ])
        .await?;
    testkit::ensure!(
        output.exit_code == 0,
        "could not trigger retained-handle probe"
    );
    poll_until(
        "retained-handle resource probe",
        Duration::from_secs(20),
        INTERVAL,
        async || {
            let output = sandbox.exec(["cat", "/sandbox/probe-result"]).await?;
            Ok(if output.exit_code == 0 {
                Poll::Ready(output.stdout.trim() == "ok")
            } else {
                Poll::Pending("main process has not completed the probe".into())
            })
        },
    )
    .await
}

async fn await_probe(sandbox: &Sandbox, success: bool) -> testkit::Result {
    poll_until(
        "supervisor credential delivery state",
        WAIT,
        INTERVAL,
        async || {
            Ok(if probe(sandbox).await? == success {
                Poll::Ready(())
            } else {
                Poll::Pending(format!("resource authorization is not yet {success}"))
            })
        },
    )
    .await
}

fn profile(name: &str, host: &str, port: &str) -> testkit::Result<tempfile::NamedTempFile> {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(Error::from_display)?;
    write!(
        file,
        r#"id: {name}
display_name: Cross-cluster issuer E2E
category: other
credentials:
  - name: access_token
    env_vars: [{KEY}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: {host}
    port: {port}
    path: /probe
    protocol: rest
    access: full
    enforcement: enforce
    allowed_ips: [{host}/32]
binaries:
  - /**
"#
    )
    .map_err(Error::from_display)?;
    file.flush().map_err(Error::from_display)?;
    Ok(file)
}

/// A separate-cluster issuer and mTLS custom minter serve public provider CRUD,
/// refresh, export and a retained workload handle; watch loss withdraws access,
/// watch reconnection restores it, and a new epoch revokes the old process.
#[testkit::test]
async fn cross_cluster_public_lifecycle_and_live_supervisor(cx: &mut Context) -> testkit::Result {
    testkit::ensure!(
        required("OPENSHELL_ISSUER_E2E_TOPOLOGY")? == "separate-clusters",
        "this lane requires separate clusters"
    );
    let host = required("OPENSHELL_ISSUER_E2E_RESOURCE_HOST")?;
    let port = required("OPENSHELL_ISSUER_E2E_RESOURCE_PORT")?;
    let provider = cx.name("issuer-provider");
    let profile_name = cx.name("issuer-profile");
    let profile = profile(&profile_name, &host, &port)?;
    let profile_path = profile.path().to_string_lossy().into_owned();
    let mut client = public_client().await?;
    let mut issuer_down = false;
    let result = async {
        cx.cli(["profile", "import", "--file", &profile_path]).await?.success()?;
        cx.cli_with_env(&[(KEY, "synthetic-bootstrap")], ["provider", "create", "--name", &provider, "--type", &profile_name, "--credential", KEY]).await?.success()?;
        configure(&mut client, &provider).await?;
        rotate(&mut client, &provider).await?;
        let first = export(&mut client, &provider).await?;
        let refresh = client.get_provider_refresh_status(rpc(proto::GetProviderRefreshStatusRequest {
            workspace_scope: scope(), provider: provider.clone(), credential_key: KEY.into(),
        })).await.map_err(status)?.into_inner();
        testkit::ensure!(refresh.credentials.len() == 1, "status omitted custom grant");
        testkit::ensure!(refresh.credentials[0].strategy_name == "custom:e2e" && refresh.credentials[0].last_refresh_time.is_some(), "status lost custom strategy or refresh history");

        let script = format!(r#"case "${{{KEY}}}" in openshell:resolve:env:*) ;; *) exit 64 ;; esac
echo $$ > /sandbox/main.pid
while true; do
  if [ -f /sandbox/probe-trigger ]; then
    rm -f /sandbox/probe-trigger
    if /usr/bin/python3 -c 'import os, urllib.request; r = urllib.request.Request("http://{host}:{port}/probe", headers={{"Authorization": "Bearer " + os.environ["{KEY}"]}}); urllib.request.urlopen(r, timeout=5).read()' >/dev/null 2>&1; then
      echo ok > /sandbox/probe-result
    else
      echo denied > /sandbox/probe-result
    fi
  fi
  sleep 0.1
done"#);
        let sandbox = cx.sandbox("issuer-delivery").command(["sh", "-ec", &script])
            .spec(|spec| spec.providers = vec![provider.clone()]).create().await?;
        sandbox.wait_ready().await?;
        await_probe(&sandbox, true).await?;
        let pid = sandbox.exec(["cat", "/sandbox/main.pid"]).await?.stdout;
        rotate(&mut client, &provider).await?;
        let second = export(&mut client, &provider).await?;
        testkit::ensure!(first != second, "rotate did not publish a new value version");
        await_probe(&sandbox, true).await?;

        issuer_down = true;
        scale_issuer("0").await?;
        let unavailable = client.get_provider_credentials(rpc(proto::GetProviderCredentialsRequest {
            workspace_scope: scope(), name: provider.clone(), credential_keys: vec![KEY.into()],
            minimum_remaining_lifetime: Some(prost_types::Duration { seconds: 1, nanos: 0 }),
        })).await;
        let unavailable = match unavailable {
            Err(error) => error,
            Ok(_) => return Err(Error::msg("operator export served a cached secret during issuer outage")),
        };
        testkit::ensure!(matches!(unavailable.code(), Code::Unavailable | Code::FailedPrecondition | Code::DeadlineExceeded), "issuer outage returned an unrelated export error: {:?}", unavailable.code());
        await_probe(&sandbox, false).await?;
        scale_issuer("1").await?;
        issuer_down = false;
        // Recovery must first restore the existing version, without a public
        // rotate masking failed watch-reset/full-reconciliation behavior.
        poll_until("issuer watch recovery and export", WAIT, INTERVAL, async || {
            match export(&mut client, &provider).await {
                Ok(value) if value == second => Ok(Poll::Ready(())),
                Ok(_) => Err(Error::msg("issuer restart changed a durable value unexpectedly")),
                Err(_) => Ok(Poll::Pending("issuer metadata remains unsynchronized".into())),
            }
        }).await?;
        await_probe(&sandbox, true).await?;
        rotate(&mut client, &provider).await?;
        testkit::ensure!(export(&mut client, &provider).await? != second, "post-recovery rotation did not advance value");
        await_probe(&sandbox, true).await?;
        testkit::ensure!(sandbox.exec(["cat", "/sandbox/main.pid"]).await?.stdout == pid, "outage restarted the workload");

        configure(&mut client, &provider).await?;
        rotate(&mut client, &provider).await?;
        await_probe(&sandbox, false).await?;
        sandbox.delete().await?;
        let before_detach = export(&mut client, &provider).await?;
        client.delete_provider_refresh(rpc(proto::DeleteProviderRefreshRequest {
            workspace_scope: scope(), provider: provider.clone(), credential_key: KEY.into(),
            request_id: id(), ..Default::default()
        })).await.map_err(status)?;
        testkit::ensure!(export(&mut client, &provider).await? == before_detach, "refresh delete did not preserve published static credentials");
        cx.cli(["provider", "delete", &provider]).await?.success()?;
        testkit::ensure!(client.get_provider_credentials(rpc(proto::GetProviderCredentialsRequest {
            workspace_scope: scope(), name: provider.clone(), credential_keys: vec![KEY.into()], ..Default::default()
        })).await.is_err(), "deleted provider remained exportable");
        Ok(())
    }.await;
    if issuer_down
        && let Err(error) = scale_issuer("1").await
    {
        eprintln!("issuer recovery cleanup failed: {error}");
    }
    for args in [
        ["provider", "delete", provider.as_str()],
        ["profile", "delete", profile_name.as_str()],
    ] {
        if let Err(error) = cx.cli(args).await.and_then(testkit::CliOutput::success) {
            // A successfully deleted provider is already absent; no secret output.
            eprintln!("resource cleanup: {error}");
        }
    }
    result
}

async fn private_channel(
    endpoint: &str,
    identity: &str,
) -> testkit::Result<tonic::transport::Channel> {
    let dir = PathBuf::from(required("OPENSHELL_ISSUER_E2E_PKI")?);
    let ca = std::fs::read(dir.join("ca.crt")).map_err(Error::from_display)?;
    let config = ExtensionChannelConfig::new(endpoint)
        .with_custom_ca_pem(ca)
        .with_client_identity(ExtensionClientIdentity::PemFiles {
            certificate: dir.join(format!("{identity}.crt")),
            private_key: dir.join(format!("{identity}.key")),
        });
    connect_channel(&config)
        .await
        .map_err(|_| Error::msg("private mTLS fixture connection failed"))
}

/// CA trust is not authorization: unknown gateways, unauthorized workspaces,
/// cross-gateway references, and gateway identities at the minter are denied.
#[testkit::test]
async fn mtls_identity_workspace_and_minter_access_denial(_cx: &mut Context) -> testkit::Result {
    let endpoint = required("OPENSHELL_ISSUER_E2E_ISSUER_ENDPOINT")?;
    let mut unknown = store::credential_store_client::CredentialStoreClient::new(
        private_channel(&endpoint, "unknown").await?,
    );
    let denied = unknown
        .get_capabilities(rpc(store::GetCapabilitiesRequest {}))
        .await
        .expect_err("unbound SPIFFE identity must be denied");
    testkit::ensure!(
        denied.code() == Code::PermissionDenied,
        "unbound identity was not denied by authorization"
    );
    let mut owner_client = store::credential_store_client::CredentialStoreClient::new(
        private_channel(&endpoint, "gateway").await?,
    );
    owner_client
        .get_capabilities(rpc(store::GetCapabilitiesRequest {}))
        .await
        .map_err(status)?;
    // A positive authenticated RPC above distinguishes transport availability
    // from the following mandatory-client-certificate handshake rejection.
    let ca = std::fs::read(PathBuf::from(required("OPENSHELL_ISSUER_E2E_PKI")?).join("ca.crt"))
        .map_err(Error::from_display)?;
    let anonymous = ExtensionChannelConfig::new(&endpoint).with_custom_ca_pem(ca);
    if let Ok(channel) = connect_channel(&anonymous).await {
        let mut anonymous = store::credential_store_client::CredentialStoreClient::new(channel);
        let denied = anonymous
            .get_capabilities(rpc(store::GetCapabilitiesRequest {}))
            .await;
        testkit::ensure!(
            denied.is_err(),
            "issuer accepted a caller without an mTLS client certificate"
        );
    }
    let owner = store::SecretOwner {
        workspace: "not-authorized".into(),
        provider_id: id(),
        credential_key: KEY.into(),
        ..Default::default()
    };
    let denied = owner_client
        .put_secret(rpc(store::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "synthetic-denial-probe".into(),
            idempotency_key: id(),
            ..Default::default()
        }))
        .await
        .expect_err("workspace outside exact binding must be denied");
    testkit::ensure!(
        denied.code() == Code::PermissionDenied,
        "workspace denial was not authorization"
    );
    let owner = store::SecretOwner {
        workspace: "default".into(),
        ..owner
    };
    let reference = owner_client
        .put_secret(rpc(store::PutSecretRequest {
            owner: Some(owner.clone()),
            value: "synthetic-cross-gateway-probe".into(),
            idempotency_key: id(),
            ..Default::default()
        }))
        .await
        .map_err(status)?
        .into_inner()
        .reference;
    let result = async {
        let mut other = store::credential_store_client::CredentialStoreClient::new(
            private_channel(&endpoint, "other-gateway").await?,
        );
        other
            .get_capabilities(rpc(store::GetCapabilitiesRequest {}))
            .await
            .map_err(status)?;
        let denied = other
            .resolve_secrets(rpc(store::ResolveSecretsRequest {
                secrets: vec![store::ResolveSecretRequest {
                    request_id: id(),
                    owner: Some(owner.clone()),
                    reference: reference.clone(),
                    expected_version: None,
                }],
                purpose: store::ResolvePurpose::OperatorExport as i32,
            }))
            .await
            .expect_err("another authorized gateway must not resolve the reference");
        testkit::ensure!(
            matches!(denied.code(), Code::PermissionDenied | Code::NotFound),
            "cross-gateway resolution did not fail closed"
        );
        let minter_endpoint = required("OPENSHELL_ISSUER_E2E_MINTER_ENDPOINT")?;
        let mut minter = minter::token_minter_client::TokenMinterClient::new(
            private_channel(&minter_endpoint, "gateway").await?,
        );
        let denied = minter
            .describe(rpc(minter::DescribeRequest {}))
            .await
            .expect_err("gateway cannot act as issuer at minter");
        testkit::ensure!(
            denied.code() == Code::PermissionDenied,
            "minter did not authorize issuer identity independently"
        );
        Ok(())
    }
    .await;
    owner_client
        .delete_secret(rpc(store::DeleteSecretRequest {
            owner: Some(owner),
            reference,
            idempotency_key: id(),
            expected_version: None,
        }))
        .await
        .map_err(status)?;
    result
}
