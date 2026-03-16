use clap::Args;

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct SimulateArgs {
    /// Target chain (e.g. ethereum, bitcoin, solana, sui)
    #[arg(long)]
    pub chain: String,

    /// Recipient address
    #[arg(long)]
    pub to: String,

    /// Transfer value (in native units: wei, satoshi, lamports, mist)
    #[arg(long)]
    pub value: String,

    /// Hex-encoded calldata (optional, 0x prefix allowed)
    #[arg(long)]
    pub data: Option<String>,

    /// Extra chain-specific parameters as JSON string
    #[arg(long)]
    pub extra: Option<String>,
}

pub async fn run(args: SimulateArgs, format: OutputFormat) -> anyhow::Result<()> {
    use mpc_wallet_chains::provider::{Chain, ChainProvider, TransactionParams};

    let extra: Option<serde_json::Value> = args
        .extra
        .as_ref()
        .map(|s| serde_json::from_str(s))
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --extra JSON: {e}"))?;

    let data = args.data.as_ref().map(|h| {
        hex::decode(h.strip_prefix("0x").unwrap_or(h)).unwrap_or_default()
    });

    let params = TransactionParams {
        to: args.to,
        value: args.value,
        data,
        chain_id: None,
        extra,
    };

    let chain: Chain = args
        .chain
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let result = match chain {
        Chain::Solana => {
            let p = mpc_wallet_chains::solana::SolanaProvider::new()
                .with_simulation(mpc_wallet_chains::solana::SolanaSimulationConfig::default());
            p.simulate_transaction(&params).await?
        }
        Chain::Sui => {
            let p = mpc_wallet_chains::sui::SuiProvider::new()
                .with_simulation(mpc_wallet_chains::sui::SuiSimulationConfig::default());
            p.simulate_transaction(&params).await?
        }
        other => {
            anyhow::bail!("simulation not yet supported for chain: {other}");
        }
    };

    let r = CliResult {
        status: if result.risk_score < 50 {
            "success"
        } else {
            "warning"
        }
        .into(),
        message: format!(
            "risk_score={}, flags=[{}]",
            result.risk_score,
            result.risk_flags.join(", ")
        ),
        data: Some(serde_json::json!({
            "success": result.success,
            "risk_score": result.risk_score,
            "risk_flags": result.risk_flags,
            "gas_used": result.gas_used,
        })),
    };
    output::print_result(&r, format);
    Ok(())
}
