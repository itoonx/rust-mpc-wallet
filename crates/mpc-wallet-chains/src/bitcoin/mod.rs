pub mod address;
pub mod signer;
pub mod tx;

use async_trait::async_trait;

use mpc_wallet_core::error::CoreError;
use mpc_wallet_core::protocol::{GroupPublicKey, MpcSignature};

use crate::provider::{
    Chain, ChainProvider, SignedTransaction, TransactionParams, UnsignedTransaction,
};

pub struct BitcoinProvider {
    pub network: bitcoin::Network,
}

impl BitcoinProvider {
    pub fn mainnet() -> Self {
        Self {
            network: bitcoin::Network::Bitcoin,
        }
    }

    pub fn testnet() -> Self {
        Self {
            network: bitcoin::Network::Testnet,
        }
    }
}

#[async_trait]
impl ChainProvider for BitcoinProvider {
    fn chain(&self) -> Chain {
        match self.network {
            bitcoin::Network::Bitcoin => Chain::BitcoinMainnet,
            _ => Chain::BitcoinTestnet,
        }
    }

    fn derive_address(&self, group_pubkey: &GroupPublicKey) -> Result<String, CoreError> {
        address::derive_taproot_address(group_pubkey, self.network)
    }

    async fn build_transaction(
        &self,
        params: TransactionParams,
    ) -> Result<UnsignedTransaction, CoreError> {
        tx::build_taproot_transaction(self.chain(), self.network, params).await
    }

    fn finalize_transaction(
        &self,
        unsigned: &UnsignedTransaction,
        sig: &MpcSignature,
    ) -> Result<SignedTransaction, CoreError> {
        tx::finalize_taproot_transaction(unsigned, sig)
    }
}
