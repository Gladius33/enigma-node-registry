#[cfg(feature = "pow")]
use std::collections::HashMap;
#[cfg(feature = "pow")]
use std::sync::Arc;
#[cfg(feature = "pow")]
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

#[cfg(feature = "pow")]
use rand::RngCore;
#[cfg(feature = "pow")]
use sha2::{Digest, Sha256};
#[cfg(feature = "pow")]
use tokio::sync::Mutex;

use crate::config::PowConfig;
use crate::error::{RegistryError, RegistryResult};

#[cfg(feature = "pow")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_ms: u64,
}

#[cfg(not(feature = "pow"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_ms: u64,
}

#[cfg(feature = "pow")]
struct StoredChallenge {
    challenge: String,
    difficulty: u8,
    expires_at: Instant,
}

#[cfg(feature = "pow")]
#[derive(Clone)]
pub struct PowManager {
    enabled: bool,
    difficulty: u8,
    ttl: Duration,
    inner: Arc<Mutex<HashMap<String, StoredChallenge>>>,
}

#[cfg(feature = "pow")]
impl PowManager {
    pub fn new(cfg: PowConfig) -> Self {
        PowManager {
            enabled: cfg.enabled,
            difficulty: cfg.difficulty,
            ttl: Duration::from_secs(cfg.ttl_seconds),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn issue(&self) -> RegistryResult<PowChallenge> {
        if !self.enabled {
            return Err(RegistryError::FeatureDisabled("pow".to_string()));
        }
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let challenge = hex::encode(bytes);
        let expires_at = Instant::now() + self.ttl;
        let expires_ms = expires_at
            .checked_duration_since(Instant::now())
            .map(|d| d.as_millis() as u64 + current_time_ms())
            .unwrap_or_else(current_time_ms);
        let stored = StoredChallenge {
            challenge: challenge.clone(),
            difficulty: self.difficulty,
            expires_at,
        };
        let mut guard = self.inner.lock().await;
        guard.insert(challenge.clone(), stored);
        Ok(PowChallenge {
            challenge,
            difficulty: self.difficulty,
            expires_ms,
        })
    }

    pub async fn verify_header(&self, value: Option<&str>) -> RegistryResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let Some(v) = value else {
            return Err(RegistryError::PowRequired);
        };
        let mut parts = v.splitn(2, ':');
        let challenge = parts.next().unwrap_or_default();
        let solution = parts.next().unwrap_or_default();
        if challenge.is_empty() || solution.is_empty() {
            return Err(RegistryError::PowRequired);
        }
        let mut guard = self.inner.lock().await;
        let Some(stored) = guard.remove(challenge) else {
            return Err(RegistryError::PowRequired);
        };
        if Instant::now() > stored.expires_at {
            return Err(RegistryError::PowRequired);
        }
        let mut hasher = Sha256::new();
        hasher.update(stored.challenge.as_bytes());
        hasher.update(solution.as_bytes());
        let digest = hasher.finalize();
        if !meets_difficulty(&digest, stored.difficulty) {
            return Err(RegistryError::PowRequired);
        }
        Ok(())
    }
}

#[cfg(feature = "pow")]
fn meets_difficulty(digest: &[u8], difficulty: u8) -> bool {
    let zero_bytes = (difficulty / 8) as usize;
    let zero_bits = (difficulty % 8) as usize;
    if digest.len() <= zero_bytes {
        return false;
    }
    if digest.iter().take(zero_bytes).any(|b| *b != 0) {
        return false;
    }
    if zero_bits == 0 {
        return true;
    }
    let next = digest[zero_bytes];
    next.leading_zeros() as usize >= zero_bits
}

#[cfg(feature = "pow")]
fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}

#[cfg(not(feature = "pow"))]
#[derive(Clone)]
pub struct PowManager;

#[cfg(not(feature = "pow"))]
impl PowManager {
    pub fn new(_cfg: PowConfig) -> Self {
        PowManager
    }

    pub fn enabled(&self) -> bool {
        false
    }

    pub async fn issue(&self) -> RegistryResult<PowChallenge> {
        Err(RegistryError::FeatureDisabled("pow".to_string()))
    }

    pub async fn verify_header(&self, _value: Option<&str>) -> RegistryResult<()> {
        Ok(())
    }
}
