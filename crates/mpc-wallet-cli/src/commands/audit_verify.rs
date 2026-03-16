use clap::Args;

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct AuditVerifyArgs {
    /// Path to the evidence pack JSON file to verify
    #[arg(long)]
    pub pack_file: String,
}

pub async fn run(args: AuditVerifyArgs, format: OutputFormat) -> anyhow::Result<()> {
    // Read the pack file
    let pack_json = std::fs::read_to_string(&args.pack_file)
        .map_err(|e| anyhow::anyhow!("Failed to read pack file '{}': {e}", args.pack_file))?;

    // Verify the pack using the core audit module
    match mpc_wallet_core::audit::AuditLedger::verify_pack(&pack_json) {
        Ok(entry_count) => {
            let result = CliResult {
                status: "success".into(),
                message: format!(
                    "Audit ledger verified: {entry_count} entries, hash chain intact"
                ),
                data: Some(serde_json::json!({
                    "verified": true,
                    "entry_count": entry_count,
                })),
            };
            output::print_result(&result, format);
            Ok(())
        }
        Err(e) => {
            let result = CliResult {
                status: "error".into(),
                message: format!("Audit verification failed: {e}"),
                data: Some(serde_json::json!({
                    "verified": false,
                    "error": e.to_string(),
                })),
            };
            output::print_result(&result, format);
            Err(anyhow::anyhow!("Audit verification failed: {e}"))
        }
    }
}
