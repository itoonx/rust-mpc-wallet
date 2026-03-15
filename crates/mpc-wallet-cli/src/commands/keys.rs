use clap::Args;

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct ListKeysArgs {
    /// Show verbose output including per-party share file paths
    #[arg(short, long)]
    pub verbose: bool,

    /// Password for key store access
    #[arg(long)]
    pub password: Option<String>,
}

pub async fn run(args: ListKeysArgs, format: OutputFormat) -> anyhow::Result<()> {
    let password = args.password.unwrap_or_else(|| "demo-password".into());

    let store = mpc_wallet_core::key_store::encrypted::EncryptedFileStore::new(
        crate::config::key_store_dir(),
        &password,
    );

    use mpc_wallet_core::key_store::KeyStore;
    let keys = store.list().await?;

    if keys.is_empty() {
        let result = CliResult {
            status: "success".into(),
            message: "No key groups found".into(),
            data: None,
        };
        output::print_result(&result, format);
        return Ok(());
    }

    let mut entries = Vec::new();
    let key_store_dir = crate::config::key_store_dir();

    for meta in &keys {
        let mut entry = serde_json::json!({
            "group_id": meta.group_id.to_string(),
            "label": meta.label,
            "scheme": meta.scheme.to_string(),
            "threshold": meta.config.threshold,
            "total_parties": meta.config.total_parties,
            "created_at": meta.created_at,
        });

        if args.verbose {
            let group_dir = key_store_dir.join(&meta.group_id.0);
            let mut share_paths = Vec::new();
            for p in 1..=meta.config.total_parties {
                let path = group_dir.join(format!("party_{p}.enc"));
                if tokio::fs::metadata(&path).await.is_ok() {
                    share_paths.push(path.display().to_string());
                }
            }
            entry["share_paths"] = serde_json::json!(share_paths);
        }

        entries.push(entry);
    }

    let result = CliResult {
        status: "success".into(),
        message: format!("Found {} key group(s)", keys.len()),
        data: Some(serde_json::json!(entries)),
    };

    output::print_result(&result, format);
    Ok(())
}
