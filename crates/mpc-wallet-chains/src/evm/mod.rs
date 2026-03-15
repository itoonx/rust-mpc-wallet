pub mod address;
pub mod signer;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, TransactionParams, UnsignedTransaction,
};

pub struct EvmProvider {
    pub chain: Chain,
    pub chain_id: u64,
}

impl EvmProvider {
    pub fn new(chain: Chain, chain_id: u64) -> Self {
        Self { chain, chain_id }
    }

    pub fn ethereum() -> Self {
        Self::new(Chain::Ethereum, 1)
    }

    pub fn polygon() -> Self {
        Self::new(Chain::Polygon, 137)
    }

    pub fn bsc() -> Self {
        Self::new(Chain::Bsc, 56)
    }
}

#[async_trait]
impl ChainProvider for EvmProvider {
    fn chain(&self) -> Chain {
        self.chain
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_evm_address(group_pubkey)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_evm_transaction(self.chain, self.chain_id, params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_evm_transaction(unsigned, sig)
    }
}
