//! NATS JetStream subject configuration and ACL for MPC message streams (Epic E5).

use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::types::PartyId;

/// JetStream stream configuration for MPC protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JetStreamConfig {
    /// Stream name (e.g., "MPC_SIGNING").
    pub stream_name: String,
    /// Subject pattern (e.g., "mpc.{session_id}.party.>").
    pub subject_pattern: String,
    /// Maximum message age before expiry (seconds).
    pub max_age_secs: u64,
    /// Maximum number of messages to retain.
    pub max_messages: u64,
    /// Storage type: "memory" or "file".
    pub storage: JetStreamStorage,
    /// Replication factor for HA.
    pub replicas: u8,
}

/// JetStream storage backend type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JetStreamStorage {
    /// In-memory storage (fast, non-durable).
    Memory,
    /// File-based storage (durable across restarts).
    File,
}

impl Default for JetStreamConfig {
    fn default() -> Self {
        Self {
            stream_name: "MPC_SIGNING".into(),
            subject_pattern: "mpc.>".into(),
            max_age_secs: 3600, // 1 hour
            max_messages: 10_000,
            storage: JetStreamStorage::Memory,
            replicas: 1,
        }
    }
}

/// Access control entry for a party's NATS permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsAcl {
    /// Party this ACL applies to.
    pub party_id: PartyId,
    /// Subjects this party can publish to.
    pub publish_allow: Vec<String>,
    /// Subjects this party can subscribe to.
    pub subscribe_allow: Vec<String>,
    /// Subjects explicitly denied.
    pub deny: Vec<String>,
}

impl NatsAcl {
    /// Generate default ACL for a party in a session.
    ///
    /// Allows:
    /// - Publish to other parties' subjects: `mpc.{session}.party.{other}`
    /// - Subscribe to own subject: `mpc.{session}.party.{self}`
    /// Denies:
    /// - Publish to own subject (isolation — a party sends TO others, not to itself)
    pub fn for_party(party_id: PartyId, session_id: &str, total_parties: u16) -> Self {
        let own_subject = format!("mpc.{}.party.{}", session_id, party_id.0);
        let mut publish_allow = Vec::new();
        let mut deny = Vec::new();

        for p in 1..=total_parties {
            let subj = format!("mpc.{}.party.{}", session_id, p);
            if p == party_id.0 {
                deny.push(subj); // can't publish to self
            } else {
                publish_allow.push(subj);
            }
        }

        Self {
            party_id,
            publish_allow,
            subscribe_allow: vec![own_subject],
            deny,
        }
    }
}

/// Validate that a JetStream config is safe for MPC use.
pub fn validate_jetstream_config(config: &JetStreamConfig) -> Result<(), CoreError> {
    if config.stream_name.is_empty() {
        return Err(CoreError::InvalidConfig(
            "stream name cannot be empty".into(),
        ));
    }
    if config.max_age_secs == 0 {
        return Err(CoreError::InvalidConfig(
            "max_age_secs must be > 0".into(),
        ));
    }
    if config.replicas == 0 {
        return Err(CoreError::InvalidConfig(
            "replicas must be >= 1".into(),
        ));
    }
    if config.max_messages == 0 {
        return Err(CoreError::InvalidConfig(
            "max_messages must be > 0".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jetstream_default_config() {
        let config = JetStreamConfig::default();
        assert_eq!(config.stream_name, "MPC_SIGNING");
        assert_eq!(config.max_age_secs, 3600);
        assert!(validate_jetstream_config(&config).is_ok());
    }

    #[test]
    fn test_jetstream_empty_stream_name_rejected() {
        let mut config = JetStreamConfig::default();
        config.stream_name = "".into();
        assert!(validate_jetstream_config(&config).is_err());
    }

    #[test]
    fn test_jetstream_zero_replicas_rejected() {
        let mut config = JetStreamConfig::default();
        config.replicas = 0;
        assert!(validate_jetstream_config(&config).is_err());
    }

    #[test]
    fn test_nats_acl_for_party() {
        let acl = NatsAcl::for_party(PartyId(1), "session-abc", 3);
        assert_eq!(acl.party_id, PartyId(1));
        // Can subscribe to own subject
        assert!(acl.subscribe_allow.iter().any(|s| s.contains("party.1")));
        // Can publish to others
        assert!(acl.publish_allow.iter().any(|s| s.contains("party.2")));
        assert!(acl.publish_allow.iter().any(|s| s.contains("party.3")));
        // Cannot publish to self
        assert!(acl.deny.iter().any(|s| s.contains("party.1")));
    }

    #[test]
    fn test_nats_acl_isolation() {
        let acl = NatsAcl::for_party(PartyId(2), "sess-1", 3);
        // Party 2 should NOT have party.1 or party.3 in subscribe_allow
        assert!(!acl.subscribe_allow.iter().any(|s| s.contains("party.1")));
        assert!(!acl.subscribe_allow.iter().any(|s| s.contains("party.3")));
    }

    #[test]
    fn test_jetstream_config_serialization() {
        let config = JetStreamConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: JetStreamConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.stream_name, "MPC_SIGNING");
    }
}
