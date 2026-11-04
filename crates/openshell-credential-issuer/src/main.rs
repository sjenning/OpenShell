// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
use clap::Parser;
use openshell_credential_issuer::daemon::{Config, Daemon};
use std::{path::PathBuf, process::ExitCode};
use tokio::io::AsyncReadExt as _;
use tonic::Status;
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};
#[derive(Parser)]
#[command(
    version,
    about = "Host OpenShell credential storage and refresh over mandatory private-CA mTLS"
)]
struct Args {
    #[arg(long, help = "Standalone issuer TOML configuration file")]
    config: PathBuf,
    #[arg(
        long,
        help = "Check configuration syntax and semantics without connecting to backends or loading keys"
    )]
    check_config: bool,
}
#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("credential issuer failed: {}", error.message());
            ExitCode::FAILURE
        }
    }
}
async fn run(args: Args) -> Result<(), Status> {
    let file = tokio::fs::File::open(&args.config)
        .await
        .map_err(|_| Status::invalid_argument("issuer configuration file unavailable"))?;
    let mut input = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut input)
        .await
        .map_err(|_| {
            Status::invalid_argument("issuer configuration file unavailable or invalid")
        })?;
    let config = Config::parse(&input)?;
    drop(input);
    if args.check_config {
        println!("Credential issuer configuration is valid.");
        return Ok(());
    }
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                    metadata.target() != "ocsf"
                }))
                .with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
        )
        // Security audit is independent of the operational log-level filter.
        .with(openshell_ocsf::tracing_layers::OcsfJsonlLayer::new(
            std::io::stdout(),
        ))
        .init();
    let shutdown = shutdown_signal()?;
    let daemon = Box::pin(Daemon::new(config)).await?;
    Box::pin(daemon.serve(shutdown)).await
}
fn shutdown_signal() -> Result<impl Future<Output = ()>, Status> {
    #[cfg(unix)]
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| Status::unavailable("issuer termination signal handler unavailable"))?;
    Ok(async move {
        #[cfg(unix)]
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    })
}
