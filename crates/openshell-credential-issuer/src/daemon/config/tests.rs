// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use super::*;
fn example() -> String {
    let path = std::env::temp_dir()
        .join("issuer-file")
        .to_string_lossy()
        .into_owned();
    format!(
        r#"[openshell.credential_issuer]
listen = "127.0.0.1:8443"
database_url = "postgres://user:do-not-log@localhost/issuer"
key_encryption_key_path = {path:?}
tls_cert_path = {path:?}
tls_key_path = {path:?}
tls_client_ca_path = {path:?}
[openshell.credential_issuer.gateway_identities]
"spiffe://example.test/gateway/a" = ["default"]
"#
    )
}
#[test]
fn strict_configuration_has_no_secret_debug_or_parser_excerpts() {
    let input = example();
    let config = Config::parse(&input).unwrap();
    assert!(!format!("{config:?}").contains("do-not-log"));
    for invalid in [
        format!("{input}\n[openshell.gateway]\ntoken=\"do-not-log\""),
        input.replace("listen =", "unknown ="),
        input.replace("tls_key_path =", "tls_key_path = ["),
        input.replace("[\"default\"]", "[\"*\"]"),
    ] {
        let error = Config::parse(&invalid).unwrap_err();
        assert!(!format!("{error:?}").contains("do-not-log"));
    }
}
#[test]
fn metrics_are_opt_in_and_require_a_distinct_nonzero_listen_address() {
    let input = example();
    assert!(
        Config::parse(&input)
            .unwrap()
            .openshell
            .credential_issuer
            .metrics_bind_address
            .is_none()
    );
    let enabled = input.replace(
        "listen =",
        "metrics_bind_address = \"127.0.0.1:9091\"\nlisten =",
    );
    assert_eq!(
        Config::parse(&enabled)
            .unwrap()
            .openshell
            .credential_issuer
            .metrics_bind_address,
        Some("127.0.0.1:9091".parse().unwrap())
    );
    for address in ["127.0.0.1:0", "127.0.0.1:8443", "invalid"] {
        assert!(Config::parse(&enabled.replace("127.0.0.1:9091", address)).is_err());
    }
}
#[test]
fn durable_storage_replica_and_timing_requirements_fail_closed() {
    let input = example();
    for invalid in [
        input.replace(
            "postgres://user:do-not-log@localhost/issuer",
            "sqlite::memory:",
        ),
        input.replace("database_url =", "replicas = 0\ndatabase_url ="),
        input.replace("database_url =", "cache_ttl_seconds = 61\ndatabase_url ="),
        input.replace(
            "database_url =",
            "refresh_interval_seconds = 0\ndatabase_url =",
        ),
        input.replace(
            "database_url =",
            "shutdown_timeout_seconds = 0\ndatabase_url =",
        ),
        input
            .replace(
                "postgres://user:do-not-log@localhost/issuer",
                "sqlite:///tmp/issuer.db",
            )
            .replace("database_url =", "replicas = 2\ndatabase_url ="),
    ] {
        assert!(Config::parse(&invalid).is_err());
    }
}
#[test]
fn remote_minters_require_explicit_private_trust_and_one_complete_identity() {
    let path = std::env::temp_dir()
        .join("issuer-file")
        .to_string_lossy()
        .into_owned();
    let base = format!(
        "{}\n[openshell.credential_issuer.minters.test]\nendpoint = \"https://localhost:8444\"\ntls_ca_cert_path = {path:?}\n",
        example()
    );
    assert!(Config::parse(&base).is_err());
    let pem = format!("{base}tls_client_cert_path = {path:?}\ntls_client_key_path = {path:?}\n");
    assert!(Config::parse(&pem).is_ok());
    assert!(Config::parse(&pem.replace("tls_client_key_path =", "unknown_key_path =")).is_err());
    for endpoint in [
        "http://localhost:8444",
        "https://user:password@localhost:8444",
        "https://localhost:8444?token=private",
        "https://localhost:8444/minter",
    ] {
        assert!(Config::parse(&pem.replace("https://localhost:8444", endpoint)).is_err());
    }
    let spiffe = format!(
        "{base}workload_api_endpoint = \"unix:///run/spire/api.sock\"\nspiffe_id = \"spiffe://example.test/issuer/a\"\n"
    );
    assert!(Config::parse(&spiffe).is_ok());
    assert!(
        Config::parse(&spiffe.replace("unix:///run/spire/api.sock", "https://remote/api")).is_err()
    );
    assert!(
        Config::parse(&format!(
            "{spiffe}tls_client_cert_path = {path:?}\ntls_client_key_path = {path:?}\n"
        ))
        .is_err()
    );
}
