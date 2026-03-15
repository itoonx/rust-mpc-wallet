pub mod encrypted;
pub mod types;

use async_trait::async_trait;

use crate::error::CoreError;
use crate::protocol::KeyShare;
use crate::types::PartyId;

use types::{KeyGroupId, KeyMetadata};

/// Trait for persistent key share storage.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Save a key share for a party in a key group.
    async fn save(
        &self,
        group_id: &KeyGroupId,
        metadata: &KeyMetadata,
        party_id: PartyId,
        share: &KeyShare,
    ) -> Result<(), CoreError>;

    /// Load a key share for a party in a key group.
    async fn load(
        &self,
        group_id: &KeyGroupId,
        party_id: PartyId,
    ) -> Result<KeyShare, CoreError>;

    /// List all key groups with metadata.
    async fn list(&self) -> Result<Vec<KeyMetadata>, CoreError>;

    /// Delete a key group and all its shares.
    async fn delete(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;

    /// Freeze a key group, preventing it from being loaded for signing.
    ///
    /// Once frozen, any attempt to call [`KeyStore::load`] on shares belonging to this
    /// group MUST return [`CoreError::KeyFrozen`]. The group's metadata remains readable
    /// via [`KeyStore::list`] so operators can identify and audit frozen groups.
    ///
    /// Freezing an already-frozen group is idempotent and MUST succeed without error.
    async fn freeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;

    /// Unfreeze a previously frozen key group, re-enabling signing.
    ///
    /// After a successful call, [`KeyStore::load`] MUST once again return the key shares
    /// for the group. Unfreezing a group that is not currently frozen is idempotent and
    /// MUST succeed without error.
    async fn unfreeze(&self, group_id: &KeyGroupId) -> Result<(), CoreError>;
}
