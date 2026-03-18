//! Shared test infrastructure for E2E tests.
//!
//! These helpers require live infrastructure (NATS, Redis, Vault).
//! Run via: `./scripts/local-infra.sh test`

pub mod chain_signing;
pub mod full_flow;
pub mod nats_transport;

use ed25519_dalek::SigningKey;
use mpc_wallet_core::protocol::{KeyShare, MpcProtocol, MpcSignature};
use mpc_wallet_core::transport::nats::NatsTransport;
use mpc_wallet_core::types::{PartyId, ThresholdConfig};

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
    /// For signing, use `connect_with_peers` to register only the signing parties.
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

    /// Create a NATS transport registering only specific peers (for signing subsets).
    pub async fn connect_with_peers(
        &self,
        party_index: usize,
        peer_indices: &[usize],
        session_id: &str,
        url: &str,
    ) -> NatsTransport {
        let party_id = PartyId(party_index as u16 + 1);
        let mut transport = NatsTransport::connect_signed(
            url,
            party_id,
            session_id.to_string(),
            self.keys[party_index].clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("NATS connect party {}: {e}", party_id.0));

        for &j in peer_indices {
            if j != party_index {
                transport.register_peer_key(PartyId(j as u16 + 1), self.keys[j].verifying_key());
            }
        }
        transport
    }
}

/// Run keygen for all parties concurrently via NATS.
/// Returns (shares, party_keys) — party_keys must be reused for signing.
pub async fn nats_keygen(
    protocol_factory: fn() -> Box<dyn MpcProtocol>,
    threshold: u16,
    total: u16,
    url: &str,
) -> (Vec<KeyShare>, PartyKeys) {
    let session_id = unique_session_id();
    let config = ThresholdConfig::new(threshold, total).unwrap();
    let party_keys = PartyKeys::generate(total);

    let mut handles = Vec::new();
    for i in 0..total as usize {
        let pkeys = party_keys.clone();
        let sid = session_id.clone();
        let nats = url.to_string();
        let protocol = protocol_factory();
        let party_id = PartyId(i as u16 + 1);

        handles.push(tokio::spawn(async move {
            let transport = pkeys.connect(i, &sid, &nats).await;
            protocol.keygen(config, party_id, &transport).await
        }));
    }

    let mut shares = Vec::new();
    for h in handles {
        shares.push(h.await.expect("keygen panicked").expect("keygen failed"));
    }
    (shares, party_keys)
}

/// Run signing for a subset of parties concurrently via NATS.
/// `party_keys` must be the same keys returned from `nats_keygen` —
/// otherwise SignedEnvelope verification will fail.
#[allow(dead_code)]
pub async fn nats_sign(
    protocol_factory: fn() -> Box<dyn MpcProtocol>,
    shares: &[KeyShare],
    signer_indices: &[usize],
    message: &[u8],
    url: &str,
    party_keys: &PartyKeys,
) -> Vec<MpcSignature> {
    let session_id = unique_session_id();
    let signers: Vec<PartyId> = signer_indices.iter().map(|&i| shares[i].party_id).collect();

    // Only register signing peers (not all parties) — important for NATS broadcast.
    let signer_party_indices: Vec<usize> = signer_indices
        .iter()
        .map(|&i| shares[i].party_id.0 as usize - 1)
        .collect();

    let mut handles = Vec::new();
    for &idx in signer_indices {
        let share = shares[idx].clone();
        let pkeys = party_keys.clone();
        let sid = session_id.clone();
        let nats = url.to_string();
        let protocol = protocol_factory();
        let signers_clone = signers.clone();
        let msg = message.to_vec();
        let party_index = share.party_id.0 as usize - 1;
        let peer_indices = signer_party_indices.clone();

        handles.push(tokio::spawn(async move {
            let transport = pkeys
                .connect_with_peers(party_index, &peer_indices, &sid, &nats)
                .await;
            protocol
                .sign(&share, &signers_clone, &msg, &transport)
                .await
        }));
    }

    let mut sigs = Vec::new();
    for h in handles {
        sigs.push(h.await.expect("sign panicked").expect("sign failed"));
    }
    sigs
}
