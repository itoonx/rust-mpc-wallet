//! TRON chain provider.
//!
//! TRON uses ECDSA secp256k1 signing (GG20) with Base58Check addresses.
//! Transaction format is Protobuf-based.

pub mod address;
pub mod proto;
pub mod rpc_client;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, SimulationResult, TransactionParams,
    UnsignedTransaction,
};

/// TRON chain provider.
pub struct TronProvider;

impl TronProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TronProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for TronProvider {
    fn chain(&self) -> Chain {
        Chain::Tron
    }

    fn metadata(&self) -> &'static crate::metadata::ChainMetadata {
        crate::metadata::metadata_for(Chain::Tron).expect("CHAIN_METADATA must contain Tron")
    }

    async fn fetch_presign_extras(
        &self,
        ctx: crate::presign::PresignContext<'_>,
    ) -> Result<crate::presign::PresignExtras, CoreError> {
        use crate::presign::PresignExtras;
        use crate::token::TokenIdentifier;
        let rpc = rpc_client::TronRpcClient::new(ctx.rpc_url);
        let block_ref = rpc.get_now_block().await?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let expiration = now_ms.saturating_add(60_000);
        let owner_address = hex::encode(tx::decode_tron_address(ctx.sender)?);

        // fee_limit policy — diverges by contract type (see L-017):
        //   - TransferContract (native TRX): MUST omit (validator rejects)
        //   - TriggerSmartContract (TRC-20): MUST include (validator rejects without)
        let fee_limit = match ctx.token {
            Some(TokenIdentifier::Tron { .. }) => Some(100_000_000u64), // 100 TRX cap
            _ => None,
        };

        Ok(PresignExtras::Tron {
            owner_address,
            ref_block_bytes: hex::encode(block_ref.ref_block_bytes),
            ref_block_hash: hex::encode(block_ref.ref_block_hash),
            timestamp: now_ms,
            expiration,
            fee_limit,
        })
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_tron_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_tron_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_tron_transaction(unsigned, sig)
    }

    async fn broadcast(
        &self,
        signed: &SignedTransaction,
        rpc_url: &str,
    ) -> Result<String, CoreError> {
        if signed.raw_tx.len() < tx::TRON_SIG_LEN {
            return Err(CoreError::Other(format!(
                "TRON signed tx too short: {} bytes",
                signed.raw_tx.len()
            )));
        }
        let split = signed.raw_tx.len() - tx::TRON_SIG_LEN;
        let (raw_data, sig) = signed.raw_tx.split_at(split);
        rpc_client::TronRpcClient::new(rpc_url)
            .broadcast(raw_data, sig)
            .await
    }

    async fn simulate_transaction(
        &self,
        params: &TransactionParams,
    ) -> Result<SimulationResult, CoreError> {
        let mut risk_flags = Vec::new();
        let mut risk_score: u8 = 0;

        // TRON uses SUN (1 TRX = 1,000,000 SUN)
        let sun: u64 = params.value.parse().unwrap_or(0);
        if sun > 100_000_000_000 {
            // > 100,000 TRX
            risk_flags.push("high_value".into());
            risk_score = risk_score.saturating_add(50);
        }

        Ok(SimulationResult {
            success: true,
            gas_used: 0,
            return_data: Vec::new(),
            risk_flags,
            risk_score,
        })
    }
}
