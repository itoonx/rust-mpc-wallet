pub mod local;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::PartyId;

/// A message exchanged between parties during MPC protocol execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolMessage {
    /// Sender party ID.
    pub from: PartyId,
    /// Recipient party ID (None = broadcast).
    pub to: Option<PartyId>,
    /// Protocol round number.
    pub round: u16,
    /// Serialized message payload.
    pub payload: Vec<u8>,
}

/// Transport layer for exchanging messages between MPC parties.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send a message to a specific party or broadcast.
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError>;

    /// Receive the next message for this party.
    async fn recv(&self) -> Result<ProtocolMessage, CoreError>;

    /// The party ID that this transport belongs to.
    fn party_id(&self) -> PartyId;
}
