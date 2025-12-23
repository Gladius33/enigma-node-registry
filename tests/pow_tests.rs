#![cfg(feature = "pow")]

use actix_web::{test, web, App};
use enigma_node_registry::config::{
    EnvelopeConfig, EnvelopeKeyConfig, PowConfig, PresenceConfig, RateLimitConfig, RegistryConfig,
    ServerMode, StorageConfig,
};
use enigma_node_registry::envelope::{EnvelopeCrypto, EnvelopeKeySet};
use enigma_node_registry::pow::PowChallenge;
use enigma_node_registry::routes::{configure, AppState, RegisterEnvelopeRequest, ResolveRequest};
use enigma_node_registry::store::Store;
use enigma_node_registry::ttl;
use enigma_node_types::{PublicIdentity, RegisterResponse, UserId};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

fn pow_config() -> RegistryConfig {
    let kid_hex = hex::encode([0xabu8; 8]);
    let priv_hex = hex::encode([0xcdu8; 32]);
    let pepper_hex = hex::encode([0xaau8; 32]);
    RegistryConfig {
        address: "127.0.0.1:0".to_string(),
        mode: ServerMode::Http,
        trusted_proxies: Vec::new(),
        rate_limit: RateLimitConfig::default(),
        envelope: EnvelopeConfig {
            pepper_hex,
            keys: vec![EnvelopeKeyConfig {
                kid_hex,
                x25519_private_key_hex: priv_hex,
                active: true,
                not_after_epoch_ms: None,
            }],
        },
        tls: None,
        storage: StorageConfig {
            kind: "memory".to_string(),
            path: "".to_string(),
        },
        presence: PresenceConfig::default(),
        pow: PowConfig {
            enabled: true,
            difficulty: 8,
            ttl_seconds: 60,
        },
        allow_sync: true,
        max_nodes: 8,
    }
}

fn sample_identity() -> PublicIdentity {
    let user_id = UserId::from_username("pow-user").expect("user");
    PublicIdentity {
        user_id,
        username_hint: Some("pow-user".to_string()),
        signing_public_key: vec![1],
        encryption_public_key: vec![2],
        signature: vec![3],
        created_at_ms: 1,
    }
}

fn build_state(cfg: &RegistryConfig) -> AppState {
    let store = Store::new_in_memory(cfg.pepper_bytes(), cfg.max_nodes);
    let keys = EnvelopeKeySet::from_config(&cfg.envelope).expect("keys");
    let crypto = EnvelopeCrypto::new(cfg.pepper_bytes());
    let rate_limiter = enigma_node_registry::rate_limit::RateLimiter::new(cfg.rate_limit.clone());
    let pow = enigma_node_registry::pow::PowManager::new(cfg.pow.clone());
    AppState {
        store: std::sync::Arc::new(store),
        keys,
        crypto,
        rate_limiter,
        pow,
        presence_ttl: cfg.presence.ttl_seconds,
        allow_sync: cfg.allow_sync,
        trusted_proxies: std::sync::Arc::new(cfg.trusted_proxies.clone()),
    }
}

fn solve_pow(challenge: &str, difficulty: u8) -> String {
    for i in 0u64.. {
        let candidate = format!("{:x}", i);
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        hasher.update(candidate.as_bytes());
        let digest = hasher.finalize();
        if meets_difficulty(&digest, difficulty) {
            return candidate;
        }
    }
    "0".to_string()
}

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
    digest[zero_bytes].leading_zeros() as usize >= zero_bits
}

#[actix_rt::test]
async fn challenge_then_resolve_with_pow_ok() {
    let cfg = pow_config();
    let state = build_state(&cfg);
    let app = test::init_service(
        App::new()
            .app_data(web::JsonConfig::default().error_handler(|err, _| {
                let resp = actix_web::HttpResponse::BadRequest().body(err.to_string());
                actix_web::error::InternalError::from_response(err, resp).into()
            }))
            .configure(configure(&cfg, state.clone())),
    )
    .await;
    let identity = sample_identity();
    let active_key = state.keys.active_key(ttl::current_time_ms()).expect("key");
    let sender_secret = StaticSecret::from([7u8; 32]);
    let sender_pub = PublicKey::from(&sender_secret);
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let envelope = state
        .crypto
        .encrypt_with_sender(
            active_key.kid,
            sender_secret.to_bytes(),
            active_key.public,
            &identity.user_id,
            &identity,
            nonce,
        )
        .expect("encrypt");
    let register = test::TestRequest::post()
        .uri("/register")
        .set_json(RegisterEnvelopeRequest {
            handle: identity.user_id.to_hex(),
            envelope,
        })
        .to_request();
    let reg_resp: RegisterResponse = test::call_and_read_body_json(&app, register).await;
    assert!(reg_resp.ok);
    let challenge_req = test::TestRequest::get().uri("/pow/challenge").to_request();
    let pow_challenge: PowChallenge = test::call_and_read_body_json(&app, challenge_req).await;
    let solution = solve_pow(&pow_challenge.challenge, pow_challenge.difficulty);
    let resolve_req = test::TestRequest::post()
        .uri("/resolve")
        .insert_header((
            "x-enigma-pow",
            format!("{}:{}", pow_challenge.challenge, solution),
        ))
        .set_json(ResolveRequest {
            handle: identity.user_id.to_hex(),
            requester_ephemeral_pubkey_hex: hex::encode(sender_pub.as_bytes()),
        })
        .to_request();
    let resp = test::call_service(&app, resolve_req).await;
    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn resolve_without_pow_rejected_when_enabled() {
    let cfg = pow_config();
    let state = build_state(&cfg);
    let app = test::init_service(App::new().configure(configure(&cfg, state))).await;
    let identity = sample_identity();
    let keyset = EnvelopeKeySet::from_config(&cfg.envelope).expect("keys");
    let key = keyset.active_key(ttl::current_time_ms()).expect("key");
    let sender_secret = StaticSecret::from([1u8; 32]);
    let envelope = EnvelopeCrypto::new(cfg.pepper_bytes())
        .encrypt_with_sender(
            key.kid,
            sender_secret.to_bytes(),
            key.public,
            &identity.user_id,
            &identity,
            [0u8; 24],
        )
        .expect("encrypt");
    let register = test::TestRequest::post()
        .uri("/register")
        .set_json(RegisterEnvelopeRequest {
            handle: identity.user_id.to_hex(),
            envelope,
        })
        .to_request();
    let _reg: RegisterResponse = test::call_and_read_body_json(&app, register).await;
    let resolve_req = test::TestRequest::post()
        .uri("/resolve")
        .set_json(ResolveRequest {
            handle: identity.user_id.to_hex(),
            requester_ephemeral_pubkey_hex: hex::encode(PublicKey::from(&sender_secret).as_bytes()),
        })
        .to_request();
    let resp = test::call_service(&app, resolve_req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}
