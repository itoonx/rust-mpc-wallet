//! CGGMP21 threshold ECDSA protocol on secp256k1.
//!
//! CGGMP21 (Canetti-Gennaro-Goldfeder-Makriyannis-Peled, 2021) is a next-generation
//! threshold ECDSA protocol that provides UC (Universally Composable) security.
//! It improves over GG20 with:
//!
//! - **Identifiable abort:** if a party misbehaves, the honest parties can identify
//!   the cheater and exclude them from future ceremonies.
//! - **UC security:** proven secure under universal composability, meaning it remains
//!   secure when composed with arbitrary other protocols.
//! - **Fewer rounds:** optimized round structure for keygen and signing.
//!
//! This module provides a stub implementation. The actual protocol logic will be
//! implemented in a future sprint by the R1 Crypto agent.

use async_trait::async_trait;

use crate::error::CoreError;
use crate::protocol::{KeyShare, MpcProtocol, MpcSignature};
use crate::transport::Transport;
use crate::types::{CryptoScheme, PartyId, ThresholdConfig};

/// CGGMP21 threshold ECDSA protocol (secp256k1).
///
/// Stub implementation — keygen and sign return errors until the protocol
/// logic is implemented by R1.
pub struct Cggmp21Protocol;

impl Cggmp21Protocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Cggmp21Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MpcProtocol for Cggmp21Protocol {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Cggmp21Secp256k1
    }

    async fn keygen(
        &self,
        _config: ThresholdConfig,
        _party_id: PartyId,
        _transport: &dyn Transport,
    ) -> Result<KeyShare, CoreError> {
        Err(CoreError::Protocol(
            "CGGMP21 keygen not yet implemented".into(),
        ))
    }

    async fn sign(
        &self,
        _key_share: &KeyShare,
        _signers: &[PartyId],
        _message: &[u8],
        _transport: &dyn Transport,
    ) -> Result<MpcSignature, CoreError> {
        Err(CoreError::Protocol(
            "CGGMP21 sign not yet implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cggmp21_scheme() {
        let protocol = Cggmp21Protocol::new();
        assert_eq!(protocol.scheme(), CryptoScheme::Cggmp21Secp256k1);
    }

    #[test]
    fn test_cggmp21_display_and_parse() {
        let scheme = CryptoScheme::Cggmp21Secp256k1;
        assert_eq!(scheme.to_string(), "cggmp21-secp256k1");

        let parsed: CryptoScheme = "cggmp21-secp256k1".parse().unwrap();
        assert_eq!(parsed, CryptoScheme::Cggmp21Secp256k1);

        let parsed_short: CryptoScheme = "cggmp21".parse().unwrap();
        assert_eq!(parsed_short, CryptoScheme::Cggmp21Secp256k1);
    }
}
