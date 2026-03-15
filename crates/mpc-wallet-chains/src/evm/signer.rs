// MPC-backed EVM signer (alloy Signer trait integration)
// This provides an alloy-compatible signer backed by MPC signing.

use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::Transport;
use mpc_wallet_core::types::PartyId;

/// An MPC-backed signer for EVM transactions.
pub struct MpcEvmSigner<'a> {
    pub protocol: &'a dyn MpcProtocol,
    pub key_share: &'a KeyShare,
    pub signers: Vec<PartyId>,
    pub transport: &'a dyn Transport,
}

impl<'a> MpcEvmSigner<'a> {
    pub fn new(
        protocol: &'a dyn MpcProtocol,
        key_share: &'a KeyShare,
        signers: Vec<PartyId>,
        transport: &'a dyn Transport,
    ) -> Self {
        Self {
            protocol,
            key_share,
            signers,
            transport,
        }
    }

    /// Sign a message digest using the MPC protocol.
    pub async fn sign_digest(&self, digest: &[u8]) -> Result<MpcSignature, mpc_wallet_core::error::CoreError> {
        self.protocol
            .sign(self.key_share, &self.signers, digest, self.transport)
            .await
    }
}
