use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{CryptoScheme, ThresholdConfig};

/// Unique identifier for a key group (all shares from one DKG session).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyGroupId(pub String);

impl KeyGroupId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn from_string(s: String) -> Self {
        Self(s)
    }
}

impl Default for KeyGroupId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for KeyGroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Metadata about a stored key group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique key group identifier.
    pub group_id: KeyGroupId,
    /// Human-readable label.
    pub label: String,
    /// Cryptographic scheme.
    pub scheme: CryptoScheme,
    /// Threshold configuration.
    pub config: ThresholdConfig,
    /// Creation timestamp (Unix seconds).
    pub created_at: u64,
}
