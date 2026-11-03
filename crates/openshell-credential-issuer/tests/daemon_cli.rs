// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;
fn command() -> tokio::process::Command {
    let mut command =
        tokio::process::Command::new(env!("CARGO_BIN_EXE_openshell-credential-issuer"));
    command.kill_on_drop(true);
    command
}
#[tokio::test]
async fn help_documents_mandatory_mtls_and_offline_validation() {
    let output = command().arg("--help").output().await.unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--config"));
    assert!(help.contains("--check-config"));
    assert!(help.contains("mandatory private-CA mTLS"));
}
#[tokio::test]
async fn check_config_is_offline_and_malformed_input_never_prints_source_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("issuer.toml");
    let missing = dir
        .path()
        .join("nonexistent")
        .to_string_lossy()
        .into_owned();
    let input = format!(
        r#"[openshell.credential_issuer]
listen = "127.0.0.1:0"
database_url = "postgres://user:do-not-log@127.0.0.1:9/issuer"
key_encryption_key_path = {missing:?}
tls_cert_path = {missing:?}
tls_key_path = {missing:?}
tls_client_ca_path = {missing:?}
[openshell.credential_issuer.gateway_identities]
"spiffe://example.test/gateway/a" = ["default"]
"#
    );
    std::fs::write(&path, &input).unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(3),
        command()
            .arg("--config")
            .arg(&path)
            .arg("--check-config")
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!dir.path().join("nonexistent").exists());
    std::fs::write(&path, input.replace("listen =", "listen = [")).unwrap();
    let output = command()
        .arg("--config")
        .arg(&path)
        .arg("--check-config")
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("do-not-log"));
    assert!(output.stdout.is_empty());
}
