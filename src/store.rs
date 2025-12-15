use std::collections::{HashMap, HashSet};

use enigma_node_types::{NodeInfo, Presence, PublicIdentity, UserId};
use tokio::sync::RwLock;

use crate::error::{EnigmaNodeRegistryError, Result};

pub struct Store {
    inner: RwLock<StoreState>,
    max_nodes: usize,
}

struct StoreState {
    identities: HashMap<UserId, PublicIdentity>,
    presences: HashMap<UserId, Presence>,
    nodes: Vec<NodeInfo>,
}

impl Store {
    pub fn new(max_nodes: usize) -> Self {
        let capped = max_nodes.max(1);
        Store {
            inner: RwLock::new(StoreState {
                identities: HashMap::new(),
                presences: HashMap::new(),
                nodes: Vec::new(),
            }),
            max_nodes: capped,
        }
    }

    pub async fn register(&self, identity: PublicIdentity) -> Result<()> {
        identity.validate()?;
        let mut guard = self.inner.write().await;
        if guard.identities.contains_key(&identity.user_id) {
            return Err(EnigmaNodeRegistryError::Conflict);
        }
        guard.identities.insert(identity.user_id, identity);
        Ok(())
    }

    pub async fn resolve(&self, user_id: &UserId) -> Result<Option<PublicIdentity>> {
        let guard = self.inner.read().await;
        Ok(guard.identities.get(user_id).cloned())
    }

    pub async fn check_user(&self, user_id: &UserId) -> Result<bool> {
        let guard = self.inner.read().await;
        Ok(guard.identities.contains_key(user_id))
    }

    pub async fn announce(&self, presence: Presence) -> Result<()> {
        presence.validate()?;
        let mut guard = self.inner.write().await;
        guard.presences.insert(presence.user_id, presence);
        Ok(())
    }

    pub async fn sync_identities(&self, identities: Vec<PublicIdentity>) -> Result<usize> {
        let mut valid = Vec::new();
        for identity in identities {
            identity.validate()?;
            valid.push(identity);
        }
        let mut guard = self.inner.write().await;
        let mut inserted = 0usize;
        for identity in valid {
            if guard.identities.contains_key(&identity.user_id) {
                continue;
            }
            guard.identities.insert(identity.user_id, identity);
            inserted = inserted.saturating_add(1);
        }
        Ok(inserted)
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeInfo>> {
        let guard = self.inner.read().await;
        Ok(guard.nodes.clone())
    }

    pub async fn add_nodes(&self, nodes: Vec<NodeInfo>) -> Result<usize> {
        let mut validated = Vec::new();
        for node in nodes {
            node.validate()?;
            let base = node.base_url.trim().to_string();
            validated.push(NodeInfo { base_url: base });
        }
        let mut guard = self.inner.write().await;
        let mut existing: HashSet<String> =
            guard.nodes.iter().map(|n| n.base_url.clone()).collect();
        let mut inserted = 0usize;
        for node in validated {
            if guard.nodes.len() >= self.max_nodes {
                break;
            }
            if existing.contains(&node.base_url) {
                continue;
            }
            guard.nodes.push(node.clone());
            existing.insert(node.base_url.clone());
            inserted = inserted.saturating_add(1);
            if guard.nodes.len() >= self.max_nodes {
                break;
            }
        }
        Ok(inserted)
    }

    pub async fn purge_presences(&self, now_ms: u64, ttl_secs: u64) -> usize {
        let ttl_ms = ttl_secs.saturating_mul(1000);
        let mut guard = self.inner.write().await;
        let before = guard.presences.len();
        guard.presences.retain(|_, presence| {
            let age = now_ms.saturating_sub(presence.ts_ms);
            age < ttl_ms
        });
        before.saturating_sub(guard.presences.len())
    }

    #[cfg(test)]
    pub async fn presence_exists(&self, user_id: &UserId) -> bool {
        let guard = self.inner.read().await;
        guard.presences.contains_key(user_id)
    }
}
