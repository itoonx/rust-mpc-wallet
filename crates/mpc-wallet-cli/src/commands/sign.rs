use clap::Args;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::types::{CryptoScheme, PartyId};

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct SignArgs {
    /// Key group ID
    #[arg(long)]
    pub key_group: String,

    /// This party's ID (1-indexed)
    #[arg(long)]
    pub party: u16,

    /// Comma-separated list of signer party IDs
    #[arg(long, value_delimiter = ',')]
    pub signers: Vec<u16>,

    /// Message to sign (hex-encoded)
    #[arg(long)]
    pub message: String,

    /// Password for key decryption
    #[arg(long)]
    pub password: Option<String>,
}

pub async fn run(args: SignArgs, format: OutputFormat) -> anyhow::Result<()> {
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

    // Load all signer key shares
    use mpc_wallet_core::key_store::KeyStore;
    let signers: Vec<PartyId> = args.signers.iter().map(|&id| PartyId(id)).collect();

    let message = hex::decode(&args.message)
        .map_err(|e| anyhow::anyhow!("invalid hex message: {e}"))?;

    // Load key shares for all signers
    let mut key_shares = Vec::new();
    for &signer in &signers {
        let share = store.load(&group_id, signer).await?;
        key_shares.push(share);
    }

    let scheme = key_shares[0].scheme;
    let config = key_shares[0].config;

    // Create transports for the signing parties
    let transports = mpc_wallet_core::transport::local::LocalTransportNetwork::new(config.total_parties);

    // Run signing for all parties concurrently
    let mut join_handles = Vec::new();

    for share in key_shares {
        let transport = transports.get_transport(share.party_id);
        let signers_clone = signers.clone();
        let message_clone = message.clone();
        let scheme_clone = scheme;

        let jh = tokio::spawn(async move {
            let protocol: Box<dyn mpc_wallet_core::protocol::MpcProtocol> = match scheme_clone {
                CryptoScheme::Gg20Ecdsa => {
                    Box::new(mpc_wallet_core::protocol::gg20::Gg20Protocol::new())
                }
                CryptoScheme::FrostSecp256k1Tr => {
                    Box::new(mpc_wallet_core::protocol::frost_secp256k1::FrostSecp256k1TrProtocol::new())
                }
                CryptoScheme::FrostEd25519 => {
                    Box::new(mpc_wallet_core::protocol::frost_ed25519::FrostEd25519Protocol::new())
                }
            };
            protocol
                .sign(&share, &signers_clone, &message_clone, &*transport)
                .await
        });
        join_handles.push(jh);
    }

    // Collect results — all parties should produce the same signature
    let mut signatures = Vec::new();
    for jh in join_handles {
        let sig = jh.await??;
        signatures.push(sig);
    }

    let sig = &signatures[0];
    let sig_hex = match sig {
        mpc_wallet_core::protocol::MpcSignature::Ecdsa { r, s, recovery_id } => {
            format!("r={} s={} v={}", hex::encode(r), hex::encode(s), recovery_id)
        }
        mpc_wallet_core::protocol::MpcSignature::Schnorr { signature } => {
            hex::encode(signature)
        }
        mpc_wallet_core::protocol::MpcSignature::EdDsa { signature } => {
            hex::encode(signature)
        }
    };

    let result = CliResult {
        status: "success".into(),
        message: "Message signed successfully".into(),
        data: Some(serde_json::json!({
            "signature": sig_hex,
            "scheme": scheme.to_string(),
            "signers": args.signers,
        })),
    };

    output::print_result(&result, format);
    Ok(())
}
