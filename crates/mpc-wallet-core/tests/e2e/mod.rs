//! Shared test infrastructure for E2E tests.
//!
//! These helpers require live infrastructure (NATS, Redis, Vault).
//! Run via: `./scripts/local-infra.sh test`

pub mod chain_signing;
pub mod full_flow;
pub mod nats_transport;

use ed25519_dalek::SigningKey;
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::types::PartyId;

pub const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:4222";

pub fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| DEFAULT_NATS_URL.into())
}

pub fn unique_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn gen_signing_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    SigningKey::from_bytes(&bytes)
}

/// Party keys for creating NATS transports with pre-registered peer keys.
#[derive(Clone)]
pub struct PartyKeys {
    pub keys: Vec<SigningKey>,
}

impl PartyKeys {
    pub fn generate(total: u16) -> Self {
        Self {
            keys: (0..total).map(|_| gen_signing_key()).collect(),
        }
    }

    /// Create a NATS transport for one party, pre-registered with all peer keys.
    pub async fn connect(&self, party_index: usize, session_id: &str, url: &str) -> NatsTransport {
        let party_id = PartyId(party_index as u16 + 1);
        let mut transport = NatsTransport::connect_signed(
            url,
            party_id,
            session_id.to_string(),
            self.keys[party_index].clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("NATS connect party {}: {e}", party_id.0));

        for (j, key) in self.keys.iter().enumerate() {
            if j != party_index {
                transport.register_peer_key(PartyId(j as u16 + 1), key.verifying_key());
            }
        }
        transport
    }
}
