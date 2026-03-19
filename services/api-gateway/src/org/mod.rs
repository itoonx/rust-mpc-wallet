//! Organization hierarchy model for multi-tenant MPC wallet management.
//!
//! Provides [`Organization`], [`Team`], and [`Vault`] types with an [`OrgStore`]
//! trait for persistence. [`InMemoryOrgStore`] is the default in-memory implementation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::errors::ApiError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A top-level organization — the root of the hierarchy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    /// Unique identifier for the organization.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// User ID of the organization administrator.
    pub admin_id: String,
    /// Unix timestamp (seconds) when the organization was created.
    pub created_at: u64,
}

/// A team within an organization. Teams group users and vaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    /// Unique identifier for the team.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The organization this team belongs to.
    pub org_id: String,
    /// Unix timestamp (seconds) when the team was created.
    pub created_at: u64,
}

/// A vault belonging to a team. Vaults hold references to MPC key groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    /// Unique identifier for the vault.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The team this vault belongs to.
    pub team_id: String,
    /// MPC key group IDs managed by this vault.
    pub key_groups: Vec<String>,
    /// Unix timestamp (seconds) when the vault was created.
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// OrgStore trait
// ---------------------------------------------------------------------------

/// Persistence interface for the organization hierarchy.
#[async_trait]
pub trait OrgStore: Send + Sync {
    /// Create a new organization.
    async fn create_org(&self, org: &Organization) -> Result<(), ApiError>;
    /// Look up an organization by ID.
    async fn get_org(&self, id: &str) -> Result<Option<Organization>, ApiError>;

    /// Create a new team.
    async fn create_team(&self, team: &Team) -> Result<(), ApiError>;
    /// Look up a team by ID.
    async fn get_team(&self, id: &str) -> Result<Option<Team>, ApiError>;
    /// List all teams belonging to the given organization.
    async fn list_teams(&self, org_id: &str) -> Result<Vec<Team>, ApiError>;

    /// Create a new vault.
    async fn create_vault(&self, vault: &Vault) -> Result<(), ApiError>;
    /// Look up a vault by ID.
    async fn get_vault(&self, id: &str) -> Result<Option<Vault>, ApiError>;
    /// List all vaults belonging to the given team.
    async fn list_vaults(&self, team_id: &str) -> Result<Vec<Vault>, ApiError>;
}

// ---------------------------------------------------------------------------
// InMemoryOrgStore
// ---------------------------------------------------------------------------

/// Thread-safe in-memory implementation of [`OrgStore`].
#[derive(Debug, Clone, Default)]
pub struct InMemoryOrgStore {
    orgs: Arc<RwLock<HashMap<String, Organization>>>,
    teams: Arc<RwLock<HashMap<String, Team>>>,
    vaults: Arc<RwLock<HashMap<String, Vault>>>,
}

impl InMemoryOrgStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OrgStore for InMemoryOrgStore {
    async fn create_org(&self, org: &Organization) -> Result<(), ApiError> {
        let mut map = self.orgs.write().await;
        if map.contains_key(&org.id) {
            return Err(ApiError::bad_request(
                crate::errors::ErrorCode::InvalidInput,
                format!("organization '{}' already exists", org.id),
            ));
        }
        map.insert(org.id.clone(), org.clone());
        Ok(())
    }

    async fn get_org(&self, id: &str) -> Result<Option<Organization>, ApiError> {
        let map = self.orgs.read().await;
        Ok(map.get(id).cloned())
    }

    async fn create_team(&self, team: &Team) -> Result<(), ApiError> {
        let mut map = self.teams.write().await;
        if map.contains_key(&team.id) {
            return Err(ApiError::bad_request(
                crate::errors::ErrorCode::InvalidInput,
                format!("team '{}' already exists", team.id),
            ));
        }
        map.insert(team.id.clone(), team.clone());
        Ok(())
    }

    async fn get_team(&self, id: &str) -> Result<Option<Team>, ApiError> {
        let map = self.teams.read().await;
        Ok(map.get(id).cloned())
    }

    async fn list_teams(&self, org_id: &str) -> Result<Vec<Team>, ApiError> {
        let map = self.teams.read().await;
        Ok(map
            .values()
            .filter(|t| t.org_id == org_id)
            .cloned()
            .collect())
    }

    async fn create_vault(&self, vault: &Vault) -> Result<(), ApiError> {
        let mut map = self.vaults.write().await;
        if map.contains_key(&vault.id) {
            return Err(ApiError::bad_request(
                crate::errors::ErrorCode::InvalidInput,
                format!("vault '{}' already exists", vault.id),
            ));
        }
        map.insert(vault.id.clone(), vault.clone());
        Ok(())
    }

    async fn get_vault(&self, id: &str) -> Result<Option<Vault>, ApiError> {
        let map = self.vaults.read().await;
        Ok(map.get(id).cloned())
    }

    async fn list_vaults(&self, team_id: &str) -> Result<Vec<Vault>, ApiError> {
        let map = self.vaults.read().await;
        Ok(map
            .values()
            .filter(|v| v.team_id == team_id)
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_org(id: &str) -> Organization {
        Organization {
            id: id.into(),
            name: format!("Org {}", id),
            admin_id: "admin-1".into(),
            created_at: 1000,
        }
    }

    fn make_team(id: &str, org_id: &str) -> Team {
        Team {
            id: id.into(),
            name: format!("Team {}", id),
            org_id: org_id.into(),
            created_at: 2000,
        }
    }

    fn make_vault(id: &str, team_id: &str) -> Vault {
        Vault {
            id: id.into(),
            name: format!("Vault {}", id),
            team_id: team_id.into(),
            key_groups: vec!["kg-1".into()],
            created_at: 3000,
        }
    }

    #[tokio::test]
    async fn test_create_org() {
        let store = InMemoryOrgStore::new();
        let org = make_org("org-1");
        assert!(store.create_org(&org).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_org() {
        let store = InMemoryOrgStore::new();
        let org = make_org("org-1");
        store.create_org(&org).await.unwrap();

        let fetched = store.get_org("org-1").await.unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.id, "org-1");
        assert_eq!(fetched.name, "Org org-1");
        assert_eq!(fetched.admin_id, "admin-1");
    }

    #[tokio::test]
    async fn test_org_not_found() {
        let store = InMemoryOrgStore::new();
        let fetched = store.get_org("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn test_create_team() {
        let store = InMemoryOrgStore::new();
        let team = make_team("team-1", "org-1");
        assert!(store.create_team(&team).await.is_ok());

        let fetched = store.get_team("team-1").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().org_id, "org-1");
    }

    #[tokio::test]
    async fn test_list_teams_by_org() {
        let store = InMemoryOrgStore::new();
        store.create_team(&make_team("t1", "org-1")).await.unwrap();
        store.create_team(&make_team("t2", "org-1")).await.unwrap();
        store.create_team(&make_team("t3", "org-2")).await.unwrap();

        let teams = store.list_teams("org-1").await.unwrap();
        assert_eq!(teams.len(), 2);
        assert!(teams.iter().all(|t| t.org_id == "org-1"));
    }

    #[tokio::test]
    async fn test_create_vault() {
        let store = InMemoryOrgStore::new();
        let vault = make_vault("v-1", "team-1");
        assert!(store.create_vault(&vault).await.is_ok());

        let fetched = store.get_vault("v-1").await.unwrap();
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().team_id, "team-1");
    }

    #[tokio::test]
    async fn test_list_vaults_by_team() {
        let store = InMemoryOrgStore::new();
        store
            .create_vault(&make_vault("v1", "team-1"))
            .await
            .unwrap();
        store
            .create_vault(&make_vault("v2", "team-1"))
            .await
            .unwrap();
        store
            .create_vault(&make_vault("v3", "team-2"))
            .await
            .unwrap();

        let vaults = store.list_vaults("team-1").await.unwrap();
        assert_eq!(vaults.len(), 2);
        assert!(vaults.iter().all(|v| v.team_id == "team-1"));
    }

    #[tokio::test]
    async fn test_vault_belongs_to_team() {
        let store = InMemoryOrgStore::new();
        store
            .create_vault(&make_vault("v1", "team-1"))
            .await
            .unwrap();

        // Vault v1 should NOT appear in team-2's list.
        let vaults = store.list_vaults("team-2").await.unwrap();
        assert!(vaults.is_empty());

        // But it SHOULD appear in team-1's list.
        let vaults = store.list_vaults("team-1").await.unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, "v1");
    }

    #[tokio::test]
    async fn test_duplicate_org_rejected() {
        let store = InMemoryOrgStore::new();
        let org = make_org("org-1");
        store.create_org(&org).await.unwrap();
        assert!(store.create_org(&org).await.is_err());
    }
}
