use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a party in the MPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartyId(pub u16);

impl fmt::Display for PartyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Party({})", self.0)
    }
}

/// Threshold configuration for MPC protocols.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Minimum number of parties required to sign (threshold).
    pub threshold: u16,
    /// Total number of parties.
    pub total_parties: u16,
}

impl ThresholdConfig {
    pub fn new(threshold: u16, total_parties: u16) -> Result<Self, &'static str> {
        if threshold == 0 {
            return Err("threshold must be at least 1");
        }
        if threshold > total_parties {
            return Err("threshold cannot exceed total_parties");
        }
        if total_parties < 2 {
            return Err("total_parties must be at least 2");
        }
        Ok(Self {
            threshold,
            total_parties,
        })
    }
}

/// Cryptographic scheme used by the MPC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoScheme {
    /// GG20 threshold ECDSA on secp256k1 (for EVM chains).
    Gg20Ecdsa,
    /// FROST Schnorr on secp256k1 with Taproot tweaks (for Bitcoin Taproot).
    FrostSecp256k1Tr,
    /// FROST EdDSA on Ed25519 (for Solana, Sui).
    FrostEd25519,
}

impl fmt::Display for CryptoScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoScheme::Gg20Ecdsa => write!(f, "gg20-ecdsa"),
            CryptoScheme::FrostSecp256k1Tr => write!(f, "frost-secp256k1-tr"),
            CryptoScheme::FrostEd25519 => write!(f, "frost-ed25519"),
        }
    }
}

impl std::str::FromStr for CryptoScheme {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "gg20-ecdsa" => Ok(CryptoScheme::Gg20Ecdsa),
            "frost-secp256k1-tr" => Ok(CryptoScheme::FrostSecp256k1Tr),
            "frost-ed25519" => Ok(CryptoScheme::FrostEd25519),
            _ => Err(format!("unknown scheme: {s}")),
        }
    }
}
