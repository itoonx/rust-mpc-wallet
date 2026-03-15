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
    /// Create an `EvmProvider` for the given chain. The chain_id is derived
    /// automatically from the chain variant. Returns `CoreError::InvalidInput`
    /// for non-EVM chains (Bitcoin, Solana, Sui).
    pub fn new(chain: Chain) -> Result<Self, CoreError> {
        let chain_id = match chain {
            Chain::Ethereum => 1,
            Chain::Polygon => 137,
            Chain::Bsc => 56,
            other => {
                return Err(CoreError::InvalidInput(format!(
                    "chain '{other}' is not an EVM chain"
                )))
            }
        };
        Ok(Self { chain, chain_id })
    }

    pub fn ethereum() -> Self {
        Self { chain: Chain::Ethereum, chain_id: 1 }
    }

    pub fn polygon() -> Self {
        Self { chain: Chain::Polygon, chain_id: 137 }
    }

    pub fn bsc() -> Self {
        Self { chain: Chain::Bsc, chain_id: 56 }
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
