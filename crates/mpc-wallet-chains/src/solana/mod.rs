pub mod address;
pub mod signer;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, TransactionParams, UnsignedTransaction,
};

pub struct SolanaProvider;

impl SolanaProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SolanaProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainProvider for SolanaProvider {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_solana_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_solana_transaction(params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_solana_transaction(unsigned, sig)
    }
}
