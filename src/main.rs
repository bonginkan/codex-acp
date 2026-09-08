// lib.rs と同じ理由。rust-v0.146.0 の codex-core は既定の recursion_limit=128 で
// layout 計算が "queries overflow the depth limit" になる。
#![recursion_limit = "256"]

use anyhow::Result;
use clap::Parser;
use codex_arg0::arg0_dispatch_or_else;
use codex_utils_cli::CliConfigOverrides;
use std::io::Write;

#[derive(Debug, Parser)]
struct Args {
    /// Run the NINNA inquiry worker with fail-closed protocol restrictions.
    #[arg(long)]
    ninna_restricted: bool,

    /// Print the build provenance manifest and exit.
    #[arg(long)]
    ninna_print_build_manifest: bool,

    #[clap(flatten)]
    config_overrides: CliConfigOverrides,
}

fn main() -> Result<()> {
    arg0_dispatch_or_else(|args| async move {
        if codex_acp::query_proxy::run_requested_mode().await? {
            return Ok(());
        }
        let cli = Args::parse();
        if cli.ninna_print_build_manifest {
            writeln!(
                std::io::stdout().lock(),
                "{}",
                serde_json::to_string(&codex_acp::build_manifest_json())?
            )?;
            return Ok(());
        }
        codex_acp::run_main(
            args.codex_linux_sandbox_exe,
            cli.config_overrides,
            cli.ninna_restricted,
        )
        .await?;
        Ok(())
    })
}
