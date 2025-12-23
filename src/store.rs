use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use blake3::Hasher;
use enigma_node_types::{NodeInfo, Presence, PublicIdentity, UserId};
use tokio::sync::RwLock;

use crate::error::{RegistryError, RegistryResult};

#[cfg(feature = "persistence")]
use persistent::PersistentStore;
use volatile::VolatileStore;

pub enum StoreBackend {
    Volatile(VolatileStore),
    #[cfg(feature = "persistence")]
    Persistent(PersistentStore),
}

#[derive(Clone)]
pub struct Store {
    backend: Arc<StoreBackend>,
    pepper: [u8; 32],
}

impl Store {
    pub fn new_in_memory(pepper: [u8; 32], max_nodes: usize) -> Self {
        Store {
            backend: Arc::new(StoreBackend::Volatile(VolatileStore::new(
                pepper, max_nodes,
            ))),
            pepper,
        }
    }

    #[cfg(feature = "persistence")]
    pub fn new_persistent(pepper: [u8; 32], path: &str, max_nodes: usize) -> RegistryResult<Self> {
        Ok(Store {
            backend: Arc::new(StoreBackend::Persistent(PersistentStore::new(
                pepper, path, max_nodes,
            )?)),
            pepper,
        })
    }

    pub fn pepper(&self) -> [u8; 32] {
        self.pepper
    }

    pub async fn register(&self, identity: PublicIdentity) -> RegistryResult<()> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.register(identity).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.register(identity).await,
        }
    }

    pub async fn resolve(&self, user_id: &UserId) -> RegistryResult<Option<PublicIdentity>> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.resolve(user_id).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.resolve(user_id).await,
        }
    }

    pub async fn check_user(&self, user_id: &UserId) -> RegistryResult<bool> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.check_user(user_id).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.check_user(user_id).await,
        }
    }

    pub async fn announce(&self, presence: Presence) -> RegistryResult<()> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.announce(presence).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.announce(presence).await,
        }
    }

    pub async fn sync_identities(&self, identities: Vec<PublicIdentity>) -> RegistryResult<usize> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.sync_identities(identities).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.sync_identities(identities).await,
        }
    }

    pub async fn list_nodes(&self) -> RegistryResult<Vec<NodeInfo>> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.list_nodes().await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.list_nodes().await,
        }
    }

    pub async fn add_nodes(&self, nodes: Vec<NodeInfo>) -> RegistryResult<usize> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.add_nodes(nodes).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.add_nodes(nodes).await,
        }
    }

    pub async fn purge_presences(&self, now_ms: u64, ttl_secs: u64) -> RegistryResult<usize> {
        match self.backend.as_ref() {
            StoreBackend::Volatile(store) => store.purge_presences(now_ms, ttl_secs).await,
            #[cfg(feature = "persistence")]
            StoreBackend::Persistent(store) => store.purge_presences(now_ms, ttl_secs).await,
        }
    }
}

fn blind_index(pepper: [u8; 32], user_id: &UserId) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"enigma:registry:blind:v1");
    hasher.update(&pepper);
    hasher.update(user_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

#[derive(Clone)]
struct StoredIdentity {
    identity: PublicIdentity,
    _blind: [u8; 32],
}

struct NodeState {
    entries: Vec<NodeInfo>,
    max: usize,
}

impl NodeState {
    fn new(max: usize) -> Self {
        NodeState {
            entries: Vec::new(),
            max: max.max(1),
        }
    }

    fn list(&self) -> Vec<NodeInfo> {
        self.entries.clone()
    }

    fn add(&mut self, nodes: Vec<NodeInfo>) -> RegistryResult<usize> {
        let mut validated = Vec::new();
        for node in nodes {
            node.validate()
                .map_err(|_| RegistryError::InvalidInput("node".to_string()))?;
            validated.push(NodeInfo {
                base_url: node.base_url.trim().to_string(),
            });
        }
        let mut existing: HashSet<String> =
            self.entries.iter().map(|n| n.base_url.clone()).collect();
        let mut inserted = 0usize;
        for node in validated {
            if self.entries.len() >= self.max {
                break;
            }
            if existing.contains(&node.base_url) {
                continue;
            }
            existing.insert(node.base_url.clone());
            self.entries.push(node);
            inserted = inserted.saturating_add(1);
            if self.entries.len() >= self.max {
                break;
            }
        }
        Ok(inserted)
    }
}

fn validate_identity(identity: &PublicIdentity) -> RegistryResult<()> {
    identity
        .validate()
        .map_err(|_| RegistryError::InvalidInput("identity".to_string()))
}

fn ensure_handle_matches(identity: &PublicIdentity) -> RegistryResult<()> {
    let derived = identity.user_id;
    let recomputed = UserId::from_hex(&identity.user_id.to_hex())
        .map_err(|_| RegistryError::InvalidInput("user_id".to_string()))?;
    if derived != recomputed {
        return Err(RegistryError::InvalidInput(
            "identity user_id mismatch".to_string(),
        ));
    }
    Ok(())
}

mod volatile {
    use super::*;

    struct VolatileState {
        identities: HashMap<UserId, StoredIdentity>,
        blind: HashMap<[u8; 32], UserId>,
        presences: HashMap<UserId, Presence>,
        nodes: NodeState,
    }

    #[derive(Clone)]
    pub struct VolatileStore {
        state: Arc<RwLock<VolatileState>>,
        pepper: [u8; 32],
    }

    impl VolatileStore {
        pub fn new(pepper: [u8; 32], max_nodes: usize) -> Self {
            VolatileStore {
                state: Arc::new(RwLock::new(VolatileState {
                    identities: HashMap::new(),
                    blind: HashMap::new(),
                    presences: HashMap::new(),
                    nodes: NodeState::new(max_nodes),
                })),
                pepper,
            }
        }

        pub async fn register(&self, identity: PublicIdentity) -> RegistryResult<()> {
            validate_identity(&identity)?;
            ensure_handle_matches(&identity)?;
            let blind = blind_index(self.pepper, &identity.user_id);
            let mut guard = self.state.write().await;
            if guard.identities.contains_key(&identity.user_id) {
                return Err(RegistryError::Conflict);
            }
            guard.blind.insert(blind, identity.user_id);
            guard.identities.insert(
                identity.user_id,
                StoredIdentity {
                    identity: identity.clone(),
                    _blind: blind,
                },
            );
            Ok(())
        }

        pub async fn resolve(&self, user_id: &UserId) -> RegistryResult<Option<PublicIdentity>> {
            let guard = self.state.read().await;
            Ok(guard.identities.get(user_id).map(|s| s.identity.clone()))
        }

        pub async fn check_user(&self, user_id: &UserId) -> RegistryResult<bool> {
            let guard = self.state.read().await;
            Ok(guard.identities.contains_key(user_id))
        }

        pub async fn announce(&self, presence: Presence) -> RegistryResult<()> {
            presence
                .validate()
                .map_err(|_| RegistryError::InvalidInput("presence".to_string()))?;
            let mut guard = self.state.write().await;
            guard.presences.insert(presence.user_id, presence);
            Ok(())
        }

        pub async fn sync_identities(
            &self,
            identities: Vec<PublicIdentity>,
        ) -> RegistryResult<usize> {
            let mut inserted = 0usize;
            let mut guard = self.state.write().await;
            for identity in identities {
                if guard.identities.contains_key(&identity.user_id) {
                    continue;
                }
                if validate_identity(&identity).is_err() {
                    continue;
                }
                ensure_handle_matches(&identity)?;
                let blind = blind_index(self.pepper, &identity.user_id);
                guard.blind.insert(blind, identity.user_id);
                guard.identities.insert(
                    identity.user_id,
                    StoredIdentity {
                        identity: identity.clone(),
                        _blind: blind,
                    },
                );
                inserted = inserted.saturating_add(1);
            }
            Ok(inserted)
        }

        pub async fn list_nodes(&self) -> RegistryResult<Vec<NodeInfo>> {
            let guard = self.state.read().await;
            Ok(guard.nodes.list())
        }

        pub async fn add_nodes(&self, nodes: Vec<NodeInfo>) -> RegistryResult<usize> {
            let mut guard = self.state.write().await;
            guard.nodes.add(nodes)
        }

        pub async fn purge_presences(&self, now_ms: u64, ttl_secs: u64) -> RegistryResult<usize> {
            let ttl_ms = ttl_secs.saturating_mul(1000);
            let mut guard = self.state.write().await;
            let before = guard.presences.len();
            guard.presences.retain(|_, presence| {
                let age = now_ms.saturating_sub(presence.ts_ms);
                age < ttl_ms
            });
            Ok(before.saturating_sub(guard.presences.len()))
        }
    }
}

#[cfg(feature = "persistence")]
mod persistent {
    use super::*;
    use tokio::task::spawn_blocking;

    #[derive(Clone)]
    pub struct PersistentStore {
        db: sled::Db,
        pepper: [u8; 32],
        max_nodes: usize,
    }

    impl PersistentStore {
        pub fn new(pepper: [u8; 32], path: &str, max_nodes: usize) -> RegistryResult<Self> {
            let db = sled::open(path)
                .map_err(|e| RegistryError::Config(format!("failed to open sled db: {}", e)))?;
            Ok(PersistentStore {
                db,
                pepper,
                max_nodes: max_nodes.max(1),
            })
        }

        pub async fn register(&self, identity: PublicIdentity) -> RegistryResult<()> {
            validate_identity(&identity)?;
            ensure_handle_matches(&identity)?;
            let handle = identity.user_id;
            let blind = blind_index(self.pepper, &handle);
            let db = self.db.clone();
            let value = serde_json::to_vec(&identity)
                .map_err(|_| RegistryError::InvalidInput("identity".to_string()))?;
            spawn_blocking(move || {
                let identities = db.open_tree("identities")?;
                let blinds = db.open_tree("blind")?;
                let key = handle.as_bytes();
                match identities.compare_and_swap(key, None as Option<&[u8]>, Some(value)) {
                    Ok(Ok(_)) => {
                        blinds.insert(blind, key)?;
                        Ok(())
                    }
                    Ok(Err(_)) => Err(RegistryError::Conflict),
                    Err(e) => Err(RegistryError::Internal
                        .with_details(serde_json::json!({ "error": e.to_string() }))),
                }
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn resolve(&self, user_id: &UserId) -> RegistryResult<Option<PublicIdentity>> {
            let db = self.db.clone();
            let key = *user_id.as_bytes();
            spawn_blocking(move || {
                let identities = db.open_tree("identities")?;
                Ok(match identities.get(key)? {
                    Some(value) => Some(
                        serde_json::from_slice::<PublicIdentity>(&value)
                            .map_err(|_| RegistryError::Internal)?,
                    ),
                    None => None,
                })
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn check_user(&self, user_id: &UserId) -> RegistryResult<bool> {
            let db = self.db.clone();
            let key = *user_id.as_bytes();
            spawn_blocking(move || {
                let identities = db.open_tree("identities")?;
                Ok(identities.contains_key(key)?)
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn announce(&self, presence: Presence) -> RegistryResult<()> {
            presence
                .validate()
                .map_err(|_| RegistryError::InvalidInput("presence".to_string()))?;
            let db = self.db.clone();
            let key = *presence.user_id.as_bytes();
            let value = serde_json::to_vec(&presence)
                .map_err(|_| RegistryError::InvalidInput("presence".to_string()))?;
            spawn_blocking(move || {
                let presences = db.open_tree("presences")?;
                presences.insert(key, value)?;
                Ok(())
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn sync_identities(
            &self,
            identities: Vec<PublicIdentity>,
        ) -> RegistryResult<usize> {
            let db = self.db.clone();
            let pepper = self.pepper;
            spawn_blocking(move || {
                let identities_tree = db.open_tree("identities")?;
                let blinds = db.open_tree("blind")?;
                let mut inserted = 0usize;
                for identity in identities {
                    if identities_tree.contains_key(identity.user_id.as_bytes())? {
                        continue;
                    }
                    if validate_identity(&identity).is_err() {
                        continue;
                    }
                    ensure_handle_matches(&identity)?;
                    let value = match serde_json::to_vec(&identity) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    identities_tree.insert(identity.user_id.as_bytes(), value)?;
                    let blind = blind_index(pepper, &identity.user_id);
                    blinds.insert(blind, identity.user_id.as_bytes())?;
                    inserted = inserted.saturating_add(1);
                }
                Ok(inserted)
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn list_nodes(&self) -> RegistryResult<Vec<NodeInfo>> {
            let db = self.db.clone();
            spawn_blocking(move || {
                let nodes = db.open_tree("nodes")?;
                let mut out = Vec::new();
                for item in nodes.iter() {
                    let (_, value) = item?;
                    if let Ok(node) = serde_json::from_slice::<NodeInfo>(&value) {
                        out.push(node);
                    }
                }
                Ok(out)
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn add_nodes(&self, nodes: Vec<NodeInfo>) -> RegistryResult<usize> {
            let db = self.db.clone();
            let max_nodes = self.max_nodes;
            spawn_blocking(move || {
                let tree = db.open_tree("nodes")?;
                let mut current = tree.len();
                let mut inserted = 0usize;
                for node in nodes {
                    node.validate()
                        .map_err(|_| RegistryError::InvalidInput("node".to_string()))?;
                    if current as usize >= max_nodes {
                        break;
                    }
                    let key = node.base_url.as_bytes();
                    if tree.contains_key(key)? {
                        continue;
                    }
                    let value = serde_json::to_vec(&node).map_err(|_| RegistryError::Internal)?;
                    tree.insert(key, value)?;
                    current = current.saturating_add(1);
                    inserted = inserted.saturating_add(1);
                }
                Ok(inserted)
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }

        pub async fn purge_presences(&self, now_ms: u64, ttl_secs: u64) -> RegistryResult<usize> {
            let db = self.db.clone();
            spawn_blocking(move || {
                let ttl_ms = ttl_secs.saturating_mul(1000);
                let presences = db.open_tree("presences")?;
                let mut removed = 0usize;
                for item in presences.iter() {
                    let (key, value) = item?;
                    let presence: Presence = match serde_json::from_slice(&value) {
                        Ok(p) => p,
                        Err(_) => {
                            presences.remove(key)?;
                            removed = removed.saturating_add(1);
                            continue;
                        }
                    };
                    let age = now_ms.saturating_sub(presence.ts_ms);
                    if age >= ttl_ms {
                        presences.remove(key)?;
                        removed = removed.saturating_add(1);
                    }
                }
                Ok(removed)
            })
            .await
            .map_err(|_| RegistryError::Internal)?
        }
    }
}
