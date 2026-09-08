//! Codex ACP - An Agent Client Protocol implementation for Codex.
// rust-v0.146.0 の codex-core は session_startup_prewarm の async block が
// 深くネストしており、既定の recursion_limit=128 では layout 計算が
// "queries overflow the depth limit" で失敗する。
#![recursion_limit = "256"]
#![deny(clippy::print_stdout, clippy::print_stderr)]

use agent_client_protocol::ByteStreams;
use codex_core::config::{Config, ConfigOverrides};
use codex_utils_cli::CliConfigOverrides;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing_subscriber::EnvFilter;

mod codex_agent;
#[cfg(unix)]
pub mod query_proxy;

#[cfg(not(unix))]
pub mod query_proxy {
    pub async fn run_requested_mode() -> anyhow::Result<bool> {
        if std::env::args().any(|arg| arg == "--ninna-query-proxy") {
            anyhow::bail!("restricted query proxy requires Unix sockets");
        }
        Ok(false)
    }
}
mod restricted;
mod thread;

pub use restricted::build_manifest_json;

/// Run the Codex ACP agent.
///
/// This sets up an ACP agent that communicates over stdio, bridging
/// the ACP protocol with the existing codex-rs infrastructure.
///
/// # Errors
///
/// If unable to parse the config or start the program.
pub async fn run_main(
    codex_linux_sandbox_exe: Option<PathBuf>,
    cli_config_overrides: CliConfigOverrides,
    restricted: bool,
) -> std::io::Result<()> {
    // Install a simple subscriber so `tracing` output is visible.
    // Users can control the log level with `RUST_LOG`.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse CLI overrides and load configuration
    if restricted && !cli_config_overrides.raw_overrides.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CLI config overrides are forbidden in restricted mode",
        ));
    }
    let cli_kv_overrides = cli_config_overrides.parse_overrides().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("error parsing -c overrides: {e}"),
        )
    })?;

    let config_overrides = ConfigOverrides {
        codex_linux_sandbox_exe: codex_linux_sandbox_exe.clone(),
        ..ConfigOverrides::default()
    };

    let config =
        Config::load_with_cli_overrides_and_harness_overrides(cli_kv_overrides, config_overrides)
            .await
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("error loading config: {e}"),
                )
            })?;
    // Apply residency requirement so the HTTP client sends the
    // x-openai-internal-codex-residency header on all requests.
    codex_login::default_client::set_default_client_residency_requirement(
        config.enforce_residency.value(),
    );

    let restricted_runtime = restricted
        .then(|| restricted::RestrictedRuntime::new(&config))
        .transpose()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::PermissionDenied, error))?
        .map(Arc::new);
    let agent = Arc::new(
        codex_agent::CodexAgent::new(config, codex_linux_sandbox_exe, restricted_runtime).await?,
    );

    let stdin = tokio::io::stdin().compat();
    let stdout = tokio::io::stdout().compat_write();

    agent
        .serve(ByteStreams::new(stdout, stdin))
        .await
        .map_err(|e| std::io::Error::other(format!("ACP error: {e}")))?;

    Ok(())
}

// Re-export the MCP server types for compatibility
pub use codex_mcp_server::{
    CodexToolCallParam, CodexToolCallReplyParam, ExecApprovalElicitRequestParams,
    ExecApprovalResponse, PatchApprovalElicitRequestParams, PatchApprovalResponse,
};
