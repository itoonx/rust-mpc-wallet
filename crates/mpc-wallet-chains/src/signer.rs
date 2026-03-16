//! Generic MPC signer — shared across all chain providers.
//!
//! Instead of duplicating the same signer struct per chain, this module
//! provides a single `MpcChainSigner` that works for any chain.

use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::Transport;
use mpc_wallet_core::types::PartyId;

/// A generic MPC-backed signer for any chain's transaction digest.
///
/// Wraps the MPC protocol, key share, signer set, and transport into
/// a single reusable struct. Chain providers create this with the
/// appropriate protocol (GG20 ECDSA, FROST Ed25519, FROST Schnorr).
pub struct MpcChainSigner<'a> {
    pub protocol: &'a dyn MpcProtocol,
    pub key_share: &'a KeyShare,
    pub signers: Vec<PartyId>,
    pub transport: &'a dyn Transport,
}

impl<'a> MpcChainSigner<'a> {
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

    /// Sign a transaction digest using the MPC protocol.
    pub async fn sign_digest(
        &self,
        digest: &[u8],
    ) -> Result<MpcSignature, mpc_wallet_core::error::CoreError> {
        self.protocol
            .sign(self.key_share, &self.signers, digest, self.transport)
            .await
    }
}
