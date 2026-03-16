mod commands;
mod config;
mod output;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mpc-wallet")]
#[command(about = "MPC wallet CLI — threshold signatures for multi-chain")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(long, default_value = "text", global = true)]
    format: output::OutputFormat,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new distributed key
    Keygen(commands::keygen::KeygenArgs),
    /// Sign a message using MPC
    Sign(commands::sign::SignArgs),
    /// Export a chain-specific address from a key group
    ExportAddress(commands::address::ExportAddressArgs),
    /// List stored key groups
    ListKeys(commands::keys::ListKeysArgs),
    /// Verify an audit evidence pack file
    AuditVerify(commands::audit_verify::AuditVerifyArgs),
    /// Simulate a transaction and assess risk
    Simulate(commands::simulate::SimulateArgs),
}

fn print_banner() {
    eprintln!(
        r#"
 ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗███████╗██╗  ██╗
 ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║███████║██║   ██║██║     ██║   █████╗   ╚███╔╝
 ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ██╔══╝   ██╔██╗
  ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ███████╗██╔╝ ██╗
   ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝
       Your keys. Distributed. Unstoppable.
"#
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    print_banner();
    let cli = Cli::parse();

    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .init();

    match cli.command {
        Commands::Keygen(args) => commands::keygen::run(args, cli.format).await?,
        Commands::Sign(args) => commands::sign::run(args, cli.format).await?,
        Commands::ExportAddress(args) => commands::address::run(args, cli.format).await?,
        Commands::ListKeys(args) => commands::keys::run(args, cli.format).await?,
        Commands::AuditVerify(args) => commands::audit_verify::run(args, cli.format).await?,
        Commands::Simulate(args) => commands::simulate::run(args, cli.format).await?,
    }

    Ok(())
}
