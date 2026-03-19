//! Address whitelist for MPC Wallet signing operations.
//!
//! Provides a trait-based whitelist store with a 24-hour cool-down period
//! for newly added addresses. Addresses are scoped per chain.

use std::sync::RwLock;

/// A whitelisted address entry with cool-down metadata.
#[derive(Debug, Clone)]
pub struct WhitelistEntry {
    /// The destination address (e.g. `"0xabc..."` for EVM).
    pub address: String,
    /// Chain identifier (e.g. `"ethereum"`, `"bitcoin"`).
    pub chain: String,
    /// Unix timestamp (seconds) when this entry was added.
    pub added_at: u64,
    /// Unix timestamp (seconds) after which this entry becomes active.
    /// Default: `added_at + 86400` (24-hour cool-down).
    pub active_after: u64,
}

/// Errors returned by whitelist operations.
#[derive(Debug, thiserror::Error)]
pub enum WhitelistError {
    /// The address+chain combination already exists.
    #[error("duplicate entry: {0} on {1}")]
    Duplicate(String, String),
    /// The address+chain combination was not found.
    #[error("not found: {0} on {1}")]
    NotFound(String, String),
}

/// Trait for address whitelist storage backends.
pub trait WhitelistStore: Send + Sync {
    /// Add an address to the whitelist with a 24-hour cool-down.
    fn add(&self, entry: WhitelistEntry) -> Result<(), WhitelistError>;
    /// Remove an address from the whitelist.
    fn remove(&self, address: &str, chain: &str) -> Result<(), WhitelistError>;
    /// Check whether an address is active (past cool-down) for a given chain.
    fn is_active(&self, address: &str, chain: &str) -> bool;
    /// List all entries for a given chain.
    fn list(&self, chain: &str) -> Vec<WhitelistEntry>;
}

/// In-memory whitelist store backed by `RwLock<Vec<WhitelistEntry>>`.
pub struct InMemoryWhitelistStore {
    entries: RwLock<Vec<WhitelistEntry>>,
}

impl InMemoryWhitelistStore {
    /// Create a new empty whitelist store.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl Default for InMemoryWhitelistStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WhitelistStore for InMemoryWhitelistStore {
    fn add(&self, entry: WhitelistEntry) -> Result<(), WhitelistError> {
        let mut entries = self.entries.write().unwrap();
        if entries
            .iter()
            .any(|e| e.address == entry.address && e.chain == entry.chain)
        {
            return Err(WhitelistError::Duplicate(
                entry.address.clone(),
                entry.chain.clone(),
            ));
        }
        entries.push(entry);
        Ok(())
    }

    fn remove(&self, address: &str, chain: &str) -> Result<(), WhitelistError> {
        let mut entries = self.entries.write().unwrap();
        let len_before = entries.len();
        entries.retain(|e| !(e.address == address && e.chain == chain));
        if entries.len() == len_before {
            return Err(WhitelistError::NotFound(
                address.to_string(),
                chain.to_string(),
            ));
        }
        Ok(())
    }

    fn is_active(&self, address: &str, chain: &str) -> bool {
        let now = Self::now();
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .any(|e| e.address == address && e.chain == chain && now > e.active_after)
    }

    fn list(&self, chain: &str) -> Vec<WhitelistEntry> {
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .filter(|e| e.chain == chain)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(address: &str, chain: &str, added_at: u64, cooldown: u64) -> WhitelistEntry {
        WhitelistEntry {
            address: address.to_string(),
            chain: chain.to_string(),
            added_at,
            active_after: added_at + cooldown,
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn test_add_and_list() {
        let store = InMemoryWhitelistStore::new();
        let now = now_secs();
        let entry = make_entry("0xAAA", "ethereum", now, 86400);
        store.add(entry).unwrap();
        let list = store.list("ethereum");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, "0xAAA");
    }

    #[test]
    fn test_remove() {
        let store = InMemoryWhitelistStore::new();
        let now = now_secs();
        store
            .add(make_entry("0xAAA", "ethereum", now, 86400))
            .unwrap();
        store.remove("0xAAA", "ethereum").unwrap();
        assert!(store.list("ethereum").is_empty());
    }

    #[test]
    fn test_cooldown_inactive() {
        let store = InMemoryWhitelistStore::new();
        let now = now_secs();
        // Added just now with 24h cooldown — should NOT be active
        store
            .add(make_entry("0xAAA", "ethereum", now, 86400))
            .unwrap();
        assert!(!store.is_active("0xAAA", "ethereum"));
    }

    #[test]
    fn test_cooldown_active() {
        let store = InMemoryWhitelistStore::new();
        // Added 2 days ago with 24h cooldown — should be active
        let two_days_ago = now_secs() - 172800;
        store
            .add(make_entry("0xBBB", "ethereum", two_days_ago, 86400))
            .unwrap();
        assert!(store.is_active("0xBBB", "ethereum"));
    }

    #[test]
    fn test_chain_scoping() {
        let store = InMemoryWhitelistStore::new();
        let past = now_secs() - 172800;
        store
            .add(make_entry("0xAAA", "ethereum", past, 86400))
            .unwrap();
        store
            .add(make_entry("0xBBB", "bitcoin", past, 86400))
            .unwrap();
        // Ethereum has 0xAAA, not 0xBBB
        assert!(store.is_active("0xAAA", "ethereum"));
        assert!(!store.is_active("0xBBB", "ethereum"));
        // Bitcoin has 0xBBB, not 0xAAA
        assert!(store.is_active("0xBBB", "bitcoin"));
        assert!(!store.is_active("0xAAA", "bitcoin"));
    }

    #[test]
    fn test_duplicate_add() {
        let store = InMemoryWhitelistStore::new();
        let now = now_secs();
        store
            .add(make_entry("0xAAA", "ethereum", now, 86400))
            .unwrap();
        let err = store
            .add(make_entry("0xAAA", "ethereum", now, 86400))
            .unwrap_err();
        assert!(matches!(err, WhitelistError::Duplicate(_, _)));
    }

    #[test]
    fn test_empty_list() {
        let store = InMemoryWhitelistStore::new();
        assert!(store.list("ethereum").is_empty());
    }

    #[test]
    fn test_remove_not_found() {
        let store = InMemoryWhitelistStore::new();
        let err = store.remove("0xAAA", "ethereum").unwrap_err();
        assert!(matches!(err, WhitelistError::NotFound(_, _)));
    }
}
