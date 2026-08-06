// lib.rs と同じ理由。rust-v0.146.0 の codex-core は既定の recursion_limit=128 で
// layout 計算が "queries overflow the depth limit" になる。
#![recursion_limit = "256"]

use anyhow::Result;
use clap::Parser;
use codex_arg0::arg0_dispatch_or_else;
use codex_utils_cli::CliConfigOverrides;

fn main() -> Result<()> {
    arg0_dispatch_or_else(|args| async move {
        let cli_config_overrides = CliConfigOverrides::parse();
        codex_acp::run_main(args.codex_linux_sandbox_exe, cli_config_overrides).await?;
        Ok(())
    })
}
