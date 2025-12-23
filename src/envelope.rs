use blake3::Hasher;
use enigma_aead;
use enigma_node_types::{PublicIdentity, UserId};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, hex::Hex, serde_as};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{EnvelopeConfig, EnvelopeKeyConfig};
use crate::error::{RegistryError, RegistryResult};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvelopeKey {
    pub kid: [u8; 8],
    pub private: [u8; 32],
    pub public: [u8; 32],
    pub active: bool,
    pub not_after: Option<u64>,
}

impl EnvelopeKey {
    pub fn from_config(cfg: &EnvelopeKeyConfig) -> RegistryResult<Self> {
        let kid_bytes = hex::decode(&cfg.kid_hex)
            .map_err(|_| RegistryError::Config("invalid kid_hex".to_string()))?;
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&kid_bytes);
        let priv_bytes = hex::decode(&cfg.x25519_private_key_hex)
            .map_err(|_| RegistryError::Config("invalid x25519_private_key_hex".to_string()))?;
        let mut private = [0u8; 32];
        private.copy_from_slice(&priv_bytes);
        let secret = StaticSecret::from(private);
        let public_key = PublicKey::from(&secret);
        let mut public = [0u8; 32];
        public.copy_from_slice(public_key.as_bytes());
        Ok(EnvelopeKey {
            kid,
            private,
            public,
            active: cfg.active,
            not_after: cfg.not_after_epoch_ms,
        })
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        match self.not_after {
            Some(limit) => now_ms > limit,
            None => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EnvelopeKeySet {
    pub keys: Vec<EnvelopeKey>,
}

impl EnvelopeKeySet {
    pub fn from_config(cfg: &EnvelopeConfig) -> RegistryResult<Self> {
        let mut keys = Vec::new();
        for entry in &cfg.keys {
            keys.push(EnvelopeKey::from_config(entry)?);
        }
        Ok(EnvelopeKeySet { keys })
    }

    pub fn active_key(&self, now_ms: u64) -> Option<EnvelopeKey> {
        self.keys
            .iter()
            .find(|k| k.active && !k.is_expired(now_ms))
            .cloned()
    }

    pub fn find_by_kid(&self, kid: &[u8; 8], now_ms: u64) -> Option<EnvelopeKey> {
        self.keys
            .iter()
            .find(|k| &k.kid == kid && !k.is_expired(now_ms))
            .cloned()
    }

    pub fn public_keys(&self) -> Vec<EnvelopePublicKey> {
        self.keys
            .iter()
            .map(|k| EnvelopePublicKey {
                kid_hex: hex::encode(k.kid),
                x25519_public_key_hex: hex::encode(k.public),
                active: k.active,
                not_after_epoch_ms: k.not_after,
            })
            .collect()
    }
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityEnvelope {
    #[serde_as(as = "Hex")]
    pub kid: [u8; 8],
    #[serde_as(as = "Hex")]
    pub sender_pubkey: [u8; 32],
    #[serde_as(as = "Hex")]
    pub nonce: [u8; 24],
    #[serde_as(as = "Base64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePublicKey {
    pub kid_hex: String,
    pub x25519_public_key_hex: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after_epoch_ms: Option<u64>,
}

#[derive(Clone)]
pub struct EnvelopeCrypto {
    pepper: [u8; 32],
}

impl EnvelopeCrypto {
    pub fn new(pepper: [u8; 32]) -> Self {
        EnvelopeCrypto { pepper }
    }

    pub fn pepper_bytes(&self) -> [u8; 32] {
        self.pepper
    }

    pub fn decrypt_identity(
        &self,
        envelope: &IdentityEnvelope,
        key: &EnvelopeKey,
        handle: &UserId,
        now_ms: u64,
    ) -> RegistryResult<PublicIdentity> {
        if key.is_expired(now_ms) {
            return Err(RegistryError::InvalidInput(
                "expired envelope key".to_string(),
            ));
        }
        if &envelope.kid != &key.kid {
            return Err(RegistryError::InvalidInput(
                "unknown envelope key".to_string(),
            ));
        }
        let shared = derive_shared_secret(&key.private, &envelope.sender_pubkey)?;
        let aead_key = derive_aead_key(self.pepper, handle.as_bytes(), &shared);
        let plaintext = enigma_aead::open(
            aead_key,
            envelope.nonce,
            &envelope.ciphertext,
            handle.as_bytes(),
        )
        .map_err(|_| RegistryError::InvalidInput("unable to decrypt envelope".to_string()))?;
        let identity: PublicIdentity = serde_json::from_slice(&plaintext)?;
        Ok(identity)
    }

    pub fn encrypt_identity_for_peer(
        &self,
        key: &EnvelopeKey,
        handle: &UserId,
        identity: &PublicIdentity,
        peer_pubkey: [u8; 32],
        nonce: Option<[u8; 24]>,
        now_ms: u64,
    ) -> RegistryResult<IdentityEnvelope> {
        if key.is_expired(now_ms) {
            return Err(RegistryError::InvalidInput(
                "expired envelope key".to_string(),
            ));
        }
        let shared = derive_shared_secret(&key.private, &peer_pubkey)?;
        let aead_key = derive_aead_key(self.pepper, handle.as_bytes(), &shared);
        let mut selected_nonce = [0u8; 24];
        if let Some(nonce_bytes) = nonce {
            selected_nonce = nonce_bytes;
        } else {
            OsRng.fill_bytes(&mut selected_nonce);
        }
        let plaintext = serde_json::to_vec(identity)?;
        let ciphertext = enigma_aead::seal(aead_key, selected_nonce, &plaintext, handle.as_bytes())
            .map_err(|_| RegistryError::Internal)?;
        Ok(IdentityEnvelope {
            kid: key.kid,
            sender_pubkey: key.public,
            nonce: selected_nonce,
            ciphertext,
        })
    }

    pub fn encrypt_with_sender(
        &self,
        kid: [u8; 8],
        sender_secret: [u8; 32],
        recipient_pubkey: [u8; 32],
        handle: &UserId,
        identity: &PublicIdentity,
        nonce: [u8; 24],
    ) -> RegistryResult<IdentityEnvelope> {
        let sender_secret = StaticSecret::from(sender_secret);
        let sender_pub = PublicKey::from(&sender_secret);
        let shared = sender_secret.diffie_hellman(&PublicKey::from(recipient_pubkey));
        let aead_key = derive_aead_key(self.pepper, handle.as_bytes(), shared.as_bytes());
        let plaintext = serde_json::to_vec(identity)?;
        let ciphertext = enigma_aead::seal(aead_key, nonce, &plaintext, handle.as_bytes())
            .map_err(|_| RegistryError::Internal)?;
        let mut sender_pub_bytes = [0u8; 32];
        sender_pub_bytes.copy_from_slice(sender_pub.as_bytes());
        Ok(IdentityEnvelope {
            kid,
            sender_pubkey: sender_pub_bytes,
            nonce,
            ciphertext,
        })
    }
}

fn derive_shared_secret(private: &[u8; 32], peer_pubkey: &[u8; 32]) -> RegistryResult<[u8; 32]> {
    let secret = StaticSecret::from(*private);
    let peer = PublicKey::from(*peer_pubkey);
    let shared = secret.diffie_hellman(&peer);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_bytes());
    Ok(out)
}

fn derive_aead_key(pepper: [u8; 32], handle: &[u8; 32], shared: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"enigma:registry:envelope:v1");
    hasher.update(&pepper);
    hasher.update(handle);
    hasher.update(shared);
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(digest.as_bytes());
    key
}
