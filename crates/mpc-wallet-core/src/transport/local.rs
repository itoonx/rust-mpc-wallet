use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::error::CoreError;
use crate::transport::{ProtocolMessage, Transport};
use crate::types::PartyId;

/// In-process transport using tokio mpsc channels.
pub struct LocalTransport {
    party: PartyId,
    receiver: Mutex<mpsc::UnboundedReceiver<ProtocolMessage>>,
    senders: HashMap<PartyId, mpsc::UnboundedSender<ProtocolMessage>>,
}

/// Factory that creates n connected local transports.
pub struct LocalTransportNetwork {
    transports: HashMap<PartyId, Arc<LocalTransport>>,
}

impl LocalTransportNetwork {
    /// Create a new network of n connected transports (party IDs 1..=n).
    pub fn new(num_parties: u16) -> Self {
        let mut receivers = HashMap::new();
        let mut all_senders = HashMap::new();

        for i in 1..=num_parties {
            let pid = PartyId(i);
            let (tx, rx) = mpsc::unbounded_channel();
            receivers.insert(pid, rx);
            all_senders.insert(pid, tx);
        }

        let mut transports = HashMap::new();
        for i in 1..=num_parties {
            let pid = PartyId(i);
            let rx = receivers.remove(&pid).unwrap();
            transports.insert(
                pid,
                Arc::new(LocalTransport {
                    party: pid,
                    receiver: Mutex::new(rx),
                    senders: all_senders.clone(),
                }),
            );
        }

        Self { transports }
    }

    /// Get the transport for a specific party.
    pub fn get_transport(&self, party_id: PartyId) -> Arc<LocalTransport> {
        self.transports
            .get(&party_id)
            .unwrap_or_else(|| panic!("no transport for {party_id}"))
            .clone()
    }
}

#[async_trait]
impl Transport for LocalTransport {
    async fn send(&self, msg: ProtocolMessage) -> Result<(), CoreError> {
        match msg.to {
            Some(to) => {
                // Unicast to a specific party
                self.senders
                    .get(&to)
                    .ok_or_else(|| CoreError::Transport(format!("unknown party: {to}")))?
                    .send(msg)
                    .map_err(|e| CoreError::Transport(e.to_string()))?;
            }
            None => {
                // Broadcast to all other parties
                for (&pid, sender) in &self.senders {
                    if pid != self.party {
                        sender
                            .send(msg.clone())
                            .map_err(|e| CoreError::Transport(e.to_string()))?;
                    }
                }
            }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<ProtocolMessage, CoreError> {
        self.receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| CoreError::Transport("channel closed".into()))
    }

    fn party_id(&self) -> PartyId {
        self.party
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unicast() {
        let net = LocalTransportNetwork::new(3);
        let t1 = net.get_transport(PartyId(1));
        let t2 = net.get_transport(PartyId(2));

        t1.send(ProtocolMessage {
            from: PartyId(1),
            to: Some(PartyId(2)),
            round: 1,
            payload: b"hello".to_vec(),
        })
        .await
        .unwrap();

        let msg = t2.recv().await.unwrap();
        assert_eq!(msg.from, PartyId(1));
        assert_eq!(msg.payload, b"hello");
    }

    #[tokio::test]
    async fn test_broadcast() {
        let net = LocalTransportNetwork::new(3);
        let t1 = net.get_transport(PartyId(1));
        let t2 = net.get_transport(PartyId(2));
        let t3 = net.get_transport(PartyId(3));

        t1.send(ProtocolMessage {
            from: PartyId(1),
            to: None,
            round: 1,
            payload: b"broadcast".to_vec(),
        })
        .await
        .unwrap();

        let msg2 = t2.recv().await.unwrap();
        let msg3 = t3.recv().await.unwrap();
        assert_eq!(msg2.payload, b"broadcast");
        assert_eq!(msg3.payload, b"broadcast");
    }
}
