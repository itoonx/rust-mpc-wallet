use clap::Args;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::types::{CryptoScheme, ThresholdConfig};

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct KeygenArgs {
    /// Threshold (minimum signers required)
    #[arg(short = 't', long)]
    pub threshold: u16,

    /// Total number of parties
    #[arg(short = 'n', long)]
    pub parties: u16,

    /// Cryptographic scheme
    #[arg(long, value_parser = parse_scheme)]
    pub scheme: CryptoScheme,

    /// Human-readable label for this key group
    #[arg(long)]
    pub label: String,

    /// Password for key encryption (will prompt if not provided)
    #[arg(long)]
    pub password: Option<String>,
}

fn parse_scheme(s: &str) -> Result<CryptoScheme, String> {
    s.parse()
}

pub async fn run(args: KeygenArgs, format: OutputFormat) -> anyhow::Result<()> {
    let config =
        ThresholdConfig::new(args.threshold, args.parties).map_err(|e| anyhow::anyhow!(e))?;

    tracing::info!(
        "Starting keygen: {}-of-{} with scheme {}",
        config.threshold,
        config.total_parties,
        args.scheme
    );

    // Select the protocol based on scheme
    let _protocol: Box<dyn mpc_wallet_core::protocol::MpcProtocol> = match args.scheme {
        CryptoScheme::Gg20Ecdsa => Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol::new()),
        CryptoScheme::FrostSecp256k1Tr => {
            Box::new(mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new())
        }
        CryptoScheme::FrostEd25519 => {
            Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
        }
        CryptoScheme::Sr25519Threshold => {
            Box::new(mpc_wallet_core::protocol::sr25519::Sr25519Protocol::new())
        }
        CryptoScheme::StarkThreshold => {
            Box::new(mpc_wallet_core::protocol::stark::StarkProtocol::new())
        }
        CryptoScheme::Bls12_381Threshold => {
            Box::new(mpc_wallet_core::protocol::bls12_381::Bls12_381Protocol::new())
        }
        CryptoScheme::Cggmp21Secp256k1 => {
            Box::new(mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol::new())
        }
    };

    // Create local transport for demo mode (all parties in one process)
    let transports =
        mpc_wallet_core::transport::local::LocalTransportNetwork::new(config.total_parties);

    // Run keygen for all parties concurrently
    let mut handles = Vec::new();
    let group_id = KeyGroupId::new();

    for i in 0..config.total_parties {
        let party_id = mpc_wallet_core::types::PartyId(i + 1);
        let transport = transports.get_transport(party_id);
        handles.push((party_id, transport));
    }

    // Run all parties concurrently using tokio tasks
    let mut key_shares = Vec::new();
    let mut join_handles = Vec::new();

    for (party_id, transport) in handles {
        let config_clone = config;
        let scheme = args.scheme;
        let jh = tokio::spawn(async move {
            let protocol: Box<dyn mpc_wallet_core::protocol::MpcProtocol> = match scheme {
                CryptoScheme::Gg20Ecdsa => {
                    Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol::new())
                }
                CryptoScheme::FrostSecp256k1Tr => Box::new(
                    mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new(),
                ),
                CryptoScheme::FrostEd25519 => {
                    Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
                }
                CryptoScheme::Sr25519Threshold => {
                    Box::new(mpc_wallet_core::protocol::sr25519::Sr25519Protocol::new())
                }
                CryptoScheme::StarkThreshold => {
                    Box::new(mpc_wallet_core::protocol::stark::StarkProtocol::new())
                }
                CryptoScheme::Bls12_381Threshold => {
                    Box::new(mpc_wallet_core::protocol::bls12_381::Bls12_381Protocol::new())
                }
                CryptoScheme::Cggmp21Secp256k1 => {
                    Box::new(mpc_wallet_core::protocol::cggmp21::Cggmp21Protocol::new())
                }
            };
            protocol.keygen(config_clone, party_id, &*transport).await
        });
        join_handles.push(jh);
    }

    for jh in join_handles {
        let share = jh.await??;
        key_shares.push(share);
    }

    // Save key shares to encrypted store
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter wallet password: ")
            .map_err(|e| anyhow::anyhow!("Failed to read password: {e}"))?,
    };
    let store = mpc_wallet_core::key_store::encrypted::EncryptedFileStore::new(
        crate::config::key_store_dir(),
        &password,
    );

    let metadata = mpc_wallet_core::key_store::types::KeyMetadata {
        group_id: group_id.clone(),
        label: args.label.clone(),
        scheme: args.scheme,
        config,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    use mpc_wallet_core::key_store::KeyStore;
    for share in &key_shares {
        store
            .save(&group_id, &metadata, share.party_id, share)
            .await?;
    }

    let result = CliResult {
        status: "success".into(),
        message: format!(
            "Generated {}-of-{} {} key group '{}'",
            config.threshold, config.total_parties, args.scheme, args.label
        ),
        data: Some(serde_json::json!({
            "group_id": group_id.to_string(),
            "scheme": args.scheme.to_string(),
            "threshold": config.threshold,
            "total_parties": config.total_parties,
            "label": args.label,
        })),
    };

    output::print_result(&result, format);
    Ok(())
}
