use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::Transport;
use mpc_wallet_core::types::PartyId;

/// An MPC-backed signer for Solana transactions.
pub struct MpcSolanaSigner<'a> {
    pub protocol: &'a dyn MpcProtocol,
    pub key_share: &'a KeyShare,
    pub signers: Vec<PartyId>,
    pub transport: &'a dyn Transport,
}

impl<'a> MpcSolanaSigner<'a> {
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

    /// Sign raw message bytes (Solana signs message, not hash).
    pub async fn sign_message(&self, message: &[u8]) -> Result<MpcSignature, mpc_wallet_core::error::CoreError> {
        self.protocol
            .sign(self.key_share, &self.signers, message, self.transport)
            .await
    }
}
