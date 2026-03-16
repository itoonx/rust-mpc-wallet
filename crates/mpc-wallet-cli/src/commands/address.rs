use clap::Args;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::types::PartyId;

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct ExportAddressArgs {
    /// Key group ID
    #[arg(long)]
    pub key_group: String,

    /// Target blockchain
    #[arg(long, value_parser = parse_chain)]
    pub chain: mpc_wallet_chains::provider::Chain,

    /// Password for key decryption
    #[arg(long)]
    pub password: Option<String>,
}

fn parse_chain(s: &str) -> Result<mpc_wallet_chains::provider::Chain, String> {
    s.parse()
}

pub async fn run(args: ExportAddressArgs, format: OutputFormat) -> anyhow::Result<()> {
    let group_id = KeyGroupId::from_string(args.key_group);
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter wallet password: ")
            .map_err(|e| anyhow::anyhow!("Failed to read password: {e}"))?,
    };

    let store = mpc_wallet_core::key_store::encrypted::EncryptedFileStore::new(
        crate::config::key_store_dir(),
        &password,
    );

    // Load party 1's key share (any party's share has the same group public key)
    use mpc_wallet_core::key_store::KeyStore;
    let share = store.load(&group_id, PartyId(1)).await?;
    let group_pubkey = &share.group_public_key;

    // Get the chain provider via registry
    use mpc_wallet_chains::registry::ChainRegistry;
    let registry = ChainRegistry::default_mainnet();
    let provider = registry.provider(args.chain)?;

    let address = provider.derive_address(group_pubkey)?;

    let result = CliResult {
        status: "success".into(),
        message: format!("Address for {} on {}", group_id, args.chain),
        data: Some(serde_json::json!({
            "address": address,
            "chain": args.chain.to_string(),
            "group_id": group_id.to_string(),
        })),
    };

    output::print_result(&result, format);
    Ok(())
}
