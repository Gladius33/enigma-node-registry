use actix_web::{test, web, App};
use enigma_node_registry::config::{
    EnvelopeConfig, EnvelopeKeyConfig, PowConfig, PresenceConfig, RateLimitConfig,
    RateLimitEndpoints, RegistryConfig, ServerMode, StorageConfig,
};
use enigma_node_registry::envelope::{EnvelopeCrypto, EnvelopeKeySet};
use enigma_node_registry::routes::{
    configure, AppState, RegisterEnvelopeRequest, ResolveRequest, ResolveResponse,
};
use enigma_node_registry::store::Store;
use enigma_node_registry::ttl;
use enigma_node_types::{Presence, PublicIdentity, RegisterResponse, UserId};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn base_config() -> RegistryConfig {
    RegistryConfig {
        address: "127.0.0.1:0".to_string(),
        mode: ServerMode::Http,
        trusted_proxies: Vec::new(),
        rate_limit: RateLimitConfig::default(),
        envelope: EnvelopeConfig {
            pepper_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
            keys: vec![EnvelopeKeyConfig {
                kid_hex: "0001020304050607".to_string(),
                x25519_private_key_hex:
                    "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f".to_string(),
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
        pow: PowConfig::default(),
        allow_sync: true,
        max_nodes: 64,
    }
}

fn sample_identity(username: &str) -> PublicIdentity {
    let user_id = UserId::from_username(username).expect("user id");
    PublicIdentity {
        user_id,
        username_hint: Some(username.to_string()),
        signing_public_key: vec![1, 2, 3],
        encryption_public_key: vec![4, 5, 6],
        signature: vec![7, 8, 9],
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

#[actix_rt::test]
async fn config_validation_rejects_bad_hex() {
    let mut cfg = base_config();
    cfg.envelope.pepper_hex = "1234".to_string();
    assert!(cfg.validate().is_err());
    let mut cfg2 = base_config();
    cfg2.envelope.keys[0].kid_hex = "abcd".to_string();
    assert!(cfg2.validate().is_err());
}

#[actix_rt::test]
async fn envelope_key_rotation_selects_active_for_pubkey() {
    let mut cfg = base_config();
    cfg.envelope.keys.push(EnvelopeKeyConfig {
        kid_hex: "1111111111111111".to_string(),
        x25519_private_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        active: true,
        not_after_epoch_ms: None,
    });
    cfg.envelope.keys[0].active = false;
    let keys = EnvelopeKeySet::from_config(&cfg.envelope).expect("keys");
    let active = keys.active_key(ttl::current_time_ms()).expect("active");
    assert_eq!(hex::encode(active.kid), "1111111111111111");
    assert_eq!(keys.public_keys().len(), 2);
}

#[actix_rt::test]
async fn register_then_resolve_roundtrip_returns_encrypted_identity() {
    let cfg = base_config();
    let state = build_state(&cfg);
    assert_eq!(state.crypto.pepper_bytes(), cfg.pepper_bytes());
    let app = test::init_service(
        App::new()
            .app_data(web::JsonConfig::default().error_handler(|err, _| {
                let resp = actix_web::HttpResponse::BadRequest().body(err.to_string());
                actix_web::error::InternalError::from_response(err, resp).into()
            }))
            .configure(configure(&cfg, state.clone())),
    )
    .await;
    let identity = sample_identity("alice");
    let active_key = state.keys.active_key(ttl::current_time_ms()).expect("key");
    let client_secret = StaticSecret::from([9u8; 32]);
    let client_pub = PublicKey::from(&client_secret);
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let shared_enc = client_secret.diffie_hellman(&PublicKey::from(active_key.public));
    let shared_dec =
        StaticSecret::from(active_key.private).diffie_hellman(&PublicKey::from(client_pub));
    let shared_via_envelope = StaticSecret::from(active_key.private)
        .diffie_hellman(&PublicKey::from(*client_pub.as_bytes()));
    assert_eq!(shared_enc.as_bytes(), shared_dec.as_bytes());
    assert_eq!(shared_enc.as_bytes(), shared_via_envelope.as_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"enigma:registry:envelope:v1");
    hasher.update(&cfg.pepper_bytes());
    hasher.update(identity.user_id.as_bytes());
    hasher.update(shared_enc.as_bytes());
    let mut aead_key = [0u8; 32];
    aead_key.copy_from_slice(hasher.finalize().as_bytes());
    let envelope = state
        .crypto
        .encrypt_with_sender(
            active_key.kid,
            client_secret.to_bytes(),
            active_key.public,
            &identity.user_id,
            &identity,
            nonce,
        )
        .expect("encrypt");
    assert_eq!(envelope.sender_pubkey, *client_pub.as_bytes());
    assert_eq!(envelope.sender_pubkey, *client_pub.as_bytes());
    let manual_plain = enigma_aead::open(
        aead_key,
        nonce,
        &envelope.ciphertext,
        identity.user_id.as_bytes(),
    )
    .expect("manual decrypt");
    let manual_identity: PublicIdentity =
        serde_json::from_slice(&manual_plain).expect("manual identity");
    assert_eq!(manual_identity, identity);
    let mut hasher_srv = blake3::Hasher::new();
    hasher_srv.update(b"enigma:registry:envelope:v1");
    hasher_srv.update(&cfg.pepper_bytes());
    hasher_srv.update(identity.user_id.as_bytes());
    hasher_srv.update(shared_dec.as_bytes());
    let mut aead_srv = [0u8; 32];
    aead_srv.copy_from_slice(hasher_srv.finalize().as_bytes());
    let server_plain = enigma_aead::open(
        aead_srv,
        nonce,
        &envelope.ciphertext,
        identity.user_id.as_bytes(),
    )
    .expect("server manual decrypt");
    let server_identity: PublicIdentity =
        serde_json::from_slice(&server_plain).expect("server identity");
    assert_eq!(server_identity, identity);
    assert_eq!(envelope.nonce, nonce);
    let preview = state
        .crypto
        .decrypt_identity(&envelope, &active_key, &identity.user_id, 0)
        .expect("local decrypt");
    assert_eq!(preview, identity);
    let req = test::TestRequest::post()
        .uri("/register")
        .set_json(RegisterEnvelopeRequest {
            handle: identity.user_id.to_hex(),
            envelope,
        })
        .to_request();
    let reg_resp = test::call_service(&app, req).await;
    let reg_status = reg_resp.status();
    let reg_body = test::read_body(reg_resp).await;
    if !reg_status.is_success() {
        panic!(
            "register failed: {:?} {}",
            reg_status,
            String::from_utf8_lossy(&reg_body)
        );
    }
    let parsed: RegisterResponse =
        serde_json::from_slice(&reg_body).expect("register response parse");
    assert!(parsed.ok);
    let resolve_req = test::TestRequest::post()
        .uri("/resolve")
        .set_json(ResolveRequest {
            handle: identity.user_id.to_hex(),
            requester_ephemeral_pubkey_hex: hex::encode(client_pub.as_bytes()),
        })
        .to_request();
    let resolved: ResolveResponse = test::call_and_read_body_json(&app, resolve_req).await;
    let envelope = resolved.envelope.expect("envelope");
    let shared_resolve = client_secret.diffie_hellman(&PublicKey::from(envelope.sender_pubkey));
    let mut hasher_resolve = blake3::Hasher::new();
    hasher_resolve.update(b"enigma:registry:envelope:v1");
    hasher_resolve.update(&cfg.pepper_bytes());
    hasher_resolve.update(identity.user_id.as_bytes());
    hasher_resolve.update(shared_resolve.as_bytes());
    let mut key_resolve = [0u8; 32];
    key_resolve.copy_from_slice(hasher_resolve.finalize().as_bytes());
    let plaintext = enigma_aead::open(
        key_resolve,
        envelope.nonce,
        &envelope.ciphertext,
        identity.user_id.as_bytes(),
    )
    .expect("decrypt");
    let decrypted: PublicIdentity = serde_json::from_slice(&plaintext).expect("identity parse");
    assert_eq!(decrypted, identity);
}

#[actix_rt::test]
async fn rate_limit_blocks_after_threshold() {
    let mut cfg = base_config();
    cfg.rate_limit.enabled = true;
    cfg.rate_limit.per_ip_rps = 1;
    cfg.rate_limit.burst = 1;
    cfg.rate_limit.ban_seconds = 60;
    cfg.rate_limit.endpoints = RateLimitEndpoints {
        register_rps: 1,
        resolve_rps: 1,
        check_user_rps: 1,
    };
    let state = build_state(&cfg);
    let app = test::init_service(App::new().configure(configure(&cfg, state))).await;
    let handle = UserId::from_username("bob").expect("handle");
    let req1 = test::TestRequest::get()
        .uri(&format!("/check_user/{}", handle.to_hex()))
        .insert_header(("x-forwarded-for", "10.0.0.1"))
        .to_request();
    let resp1 = test::call_service(&app, req1).await;
    assert!(resp1.status().is_success());
    let req2 = test::TestRequest::get()
        .uri(&format!("/check_user/{}", handle.to_hex()))
        .insert_header(("x-forwarded-for", "10.0.0.1"))
        .to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(
        resp2.status(),
        actix_web::http::StatusCode::TOO_MANY_REQUESTS
    );
}

#[actix_rt::test]
async fn presence_ttl_gc_removes_old_entries() {
    let cfg = base_config();
    let store = Store::new_in_memory(cfg.pepper_bytes(), cfg.max_nodes);
    let now = ttl::current_time_ms();
    let user_id = UserId::from_username("carol").expect("user");
    let presence = Presence {
        user_id,
        addr: "127.0.0.1:9000".to_string(),
        ts_ms: now,
    };
    store.announce(presence).await.expect("announce");
    let removed = store.purge_presences(now + 10000, 1).await.expect("purge");
    assert_eq!(removed, 1);
}
