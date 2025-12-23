use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::error::{RegistryError, RegistryResult};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    Http,
    Tls,
}

impl Default for ServerMode {
    fn default() -> Self {
        ServerMode::Tls
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    #[serde(default = "default_address")]
    pub address: String,
    #[serde(default)]
    pub mode: ServerMode,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    pub envelope: EnvelopeConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub presence: PresenceConfig,
    #[serde(default)]
    pub pow: PowConfig,
    #[serde(default = "default_allow_sync")]
    pub allow_sync: bool,
    #[serde(default = "default_max_nodes")]
    pub max_nodes: usize,
}

impl RegistryConfig {
    pub fn load_from_path(path: impl AsRef<Path>) -> RegistryResult<Self> {
        let content = fs::read_to_string(path)?;
        let parsed: RegistryConfig = toml::from_str(&content)
            .map_err(|err| RegistryError::Config(format!("failed to parse config: {}", err)))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> RegistryResult<()> {
        match self.mode {
            ServerMode::Http => {
                if !cfg!(feature = "http") {
                    return Err(RegistryError::FeatureDisabled("http".to_string()));
                }
            }
            ServerMode::Tls => {
                if !cfg!(feature = "tls") {
                    return Err(RegistryError::FeatureDisabled("tls".to_string()));
                }
                if self.tls.is_none() {
                    return Err(RegistryError::Config(
                        "tls configuration is required for tls mode".to_string(),
                    ));
                }
            }
        }
        if self.address.trim().is_empty() {
            return Err(RegistryError::Config("address cannot be empty".to_string()));
        }
        self.rate_limit.validate()?;
        self.envelope.validate()?;
        if let Some(tls) = &self.tls {
            tls.validate(self.mode.clone())?;
        }
        self.storage.validate()?;
        self.presence.validate()?;
        self.pow.validate()?;
        Ok(())
    }

    pub fn pepper_bytes(&self) -> [u8; 32] {
        self.envelope.pepper_bytes()
    }
}

fn default_address() -> String {
    "0.0.0.0:8443".to_string()
}

fn default_allow_sync() -> bool {
    true
}

fn default_max_nodes() -> usize {
    2048
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default = "default_ban_seconds")]
    pub ban_seconds: u64,
    #[serde(default)]
    pub endpoints: RateLimitEndpoints,
}

impl RateLimitConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.per_ip_rps == 0 {
            return Err(RegistryError::Config(
                "per_ip_rps must be positive".to_string(),
            ));
        }
        if self.burst == 0 {
            return Err(RegistryError::Config("burst must be positive".to_string()));
        }
        self.endpoints.validate()
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            enabled: true,
            per_ip_rps: 5,
            burst: 10,
            ban_seconds: 300,
            endpoints: RateLimitEndpoints::default(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_per_ip_rps() -> u32 {
    5
}

fn default_burst() -> u32 {
    10
}

fn default_ban_seconds() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitEndpoints {
    #[serde(default = "default_register_rps")]
    pub register_rps: u32,
    #[serde(default = "default_resolve_rps")]
    pub resolve_rps: u32,
    #[serde(default = "default_check_user_rps")]
    pub check_user_rps: u32,
}

impl RateLimitEndpoints {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.register_rps == 0 {
            return Err(RegistryError::Config(
                "register_rps must be positive".to_string(),
            ));
        }
        if self.resolve_rps == 0 {
            return Err(RegistryError::Config(
                "resolve_rps must be positive".to_string(),
            ));
        }
        if self.check_user_rps == 0 {
            return Err(RegistryError::Config(
                "check_user_rps must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for RateLimitEndpoints {
    fn default() -> Self {
        RateLimitEndpoints {
            register_rps: 1,
            resolve_rps: 3,
            check_user_rps: 10,
        }
    }
}

fn default_register_rps() -> u32 {
    1
}

fn default_resolve_rps() -> u32 {
    3
}

fn default_check_user_rps() -> u32 {
    10
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeConfig {
    pub pepper_hex: String,
    pub keys: Vec<EnvelopeKeyConfig>,
}

impl EnvelopeConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.keys.is_empty() {
            return Err(RegistryError::Config(
                "at least one envelope key required".to_string(),
            ));
        }
        if self.pepper_hex.len() != 64 {
            return Err(RegistryError::Config(
                "pepper_hex must be 32 bytes hex".to_string(),
            ));
        }
        if hex::decode(&self.pepper_hex)
            .map_err(|_| RegistryError::Config("invalid pepper_hex".to_string()))?
            .len()
            != 32
        {
            return Err(RegistryError::Config(
                "pepper_hex must decode to 32 bytes".to_string(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        let mut active = 0usize;
        for key in &self.keys {
            key.validate()?;
            if !seen.insert(key.kid_hex.clone()) {
                return Err(RegistryError::Config("duplicate kid_hex".to_string()));
            }
            if key.active {
                active = active.saturating_add(1);
            }
        }
        if active == 0 {
            return Err(RegistryError::Config(
                "one active envelope key required".to_string(),
            ));
        }
        Ok(())
    }

    pub fn pepper_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Ok(bytes) = hex::decode(&self.pepper_hex) {
            let len = bytes.len().min(32);
            out[..len].copy_from_slice(&bytes[..len]);
        }
        out
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeKeyConfig {
    pub kid_hex: String,
    pub x25519_private_key_hex: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub not_after_epoch_ms: Option<u64>,
}

impl EnvelopeKeyConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.kid_hex.len() != 16 {
            return Err(RegistryError::Config(
                "kid_hex must be 8 bytes hex".to_string(),
            ));
        }
        if hex::decode(&self.kid_hex)
            .map_err(|_| RegistryError::Config("invalid kid_hex".to_string()))?
            .len()
            != 8
        {
            return Err(RegistryError::Config(
                "kid_hex must decode to 8 bytes".to_string(),
            ));
        }
        if self.x25519_private_key_hex.len() != 64 {
            return Err(RegistryError::Config(
                "x25519_private_key_hex must be 32 bytes hex".to_string(),
            ));
        }
        if hex::decode(&self.x25519_private_key_hex)
            .map_err(|_| RegistryError::Config("invalid x25519_private_key_hex".to_string()))?
            .len()
            != 32
        {
            return Err(RegistryError::Config(
                "x25519_private_key_hex must decode to 32 bytes".to_string(),
            ));
        }
        if let Some(not_after) = self.not_after_epoch_ms {
            if not_after <= current_time_ms() {
                return Err(RegistryError::Config(
                    "not_after_epoch_ms is in the past".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_pem_path: String,
    pub key_pem_path: String,
    #[serde(default)]
    pub client_ca_pem_path: Option<String>,
}

impl TlsConfig {
    pub fn validate(&self, mode: ServerMode) -> RegistryResult<()> {
        if mode == ServerMode::Tls
            && (self.cert_pem_path.is_empty() || self.key_pem_path.is_empty())
        {
            return Err(RegistryError::Config(
                "cert_pem_path and key_pem_path are required for tls mode".to_string(),
            ));
        }
        if self.client_ca_pem_path.is_some() && !cfg!(feature = "mtls") {
            return Err(RegistryError::FeatureDisabled("mtls".to_string()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_storage_kind")]
    pub kind: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
}

impl StorageConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.kind != "sled" && self.kind != "memory" {
            return Err(RegistryError::Config(
                "storage.kind must be \"sled\" or \"memory\"".to_string(),
            ));
        }
        if self.kind == "sled" {
            if self.path.trim().is_empty() {
                return Err(RegistryError::Config(
                    "storage.path cannot be empty".to_string(),
                ));
            }
            if !cfg!(feature = "persistence") {
                return Err(RegistryError::FeatureDisabled("persistence".to_string()));
            }
        }
        Ok(())
    }
}

fn default_storage_kind() -> String {
    "sled".to_string()
}

fn default_storage_path() -> String {
    "./registry_db".to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PresenceConfig {
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default = "default_gc_interval_seconds")]
    pub gc_interval_seconds: u64,
}

impl PresenceConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if self.ttl_seconds == 0 {
            return Err(RegistryError::Config(
                "ttl_seconds must be positive".to_string(),
            ));
        }
        if self.gc_interval_seconds == 0 {
            return Err(RegistryError::Config(
                "gc_interval_seconds must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            ttl_seconds: 300,
            gc_interval_seconds: 60,
        }
    }
}

fn default_ttl_seconds() -> u64 {
    300
}

fn default_gc_interval_seconds() -> u64 {
    60
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pow_difficulty")]
    pub difficulty: u8,
    #[serde(default = "default_pow_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl PowConfig {
    pub fn validate(&self) -> RegistryResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.difficulty == 0 || self.difficulty > 30 {
            return Err(RegistryError::Config(
                "difficulty must be between 1 and 30".to_string(),
            ));
        }
        if self.ttl_seconds == 0 {
            return Err(RegistryError::Config(
                "ttl_seconds must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for PowConfig {
    fn default() -> Self {
        PowConfig {
            enabled: false,
            difficulty: default_pow_difficulty(),
            ttl_seconds: default_pow_ttl_seconds(),
        }
    }
}

fn default_pow_difficulty() -> u8 {
    18
}

fn default_pow_ttl_seconds() -> u64 {
    120
}

fn current_time_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}
