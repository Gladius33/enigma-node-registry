use std::sync::Arc;

use actix_web::web::{self, Json, ServiceConfig};
use actix_web::{get, post, HttpRequest, HttpResponse, Responder};
use enigma_node_types::{
    CheckUserResponse, NodesPayload, Presence, RegisterResponse, SyncRequest, SyncResponse, UserId,
};
use serde::{Deserialize, Serialize};

use crate::config::RegistryConfig;
use crate::envelope::{EnvelopeCrypto, EnvelopeKeySet, EnvelopePublicKey, IdentityEnvelope};
use crate::error::{RegistryError, RegistryResult};
#[cfg(feature = "pow")]
use crate::pow::PowChallenge;
use crate::pow::PowManager as PowManagerStub;
use crate::rate_limit::{RateLimiter, RateScope};
use crate::store::Store;
use crate::ttl::current_time_ms;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub keys: EnvelopeKeySet,
    pub crypto: EnvelopeCrypto,
    pub rate_limiter: RateLimiter,
    pub pow: PowManagerStub,
    pub presence_ttl: u64,
    pub allow_sync: bool,
    pub trusted_proxies: Arc<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterEnvelopeRequest {
    pub handle: String,
    pub envelope: IdentityEnvelope,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub handle: String,
    pub requester_ephemeral_pubkey_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolveResponse {
    pub handle: String,
    pub envelope: Option<IdentityEnvelope>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct MergedResponse {
    pub merged: usize,
}

pub fn configure(_cfg: &RegistryConfig, state: AppState) -> impl FnOnce(&mut ServiceConfig) {
    #[cfg(feature = "pow")]
    let pow_enabled = state.pow.enabled();
    move |service: &mut ServiceConfig| {
        let data = web::Data::new(state.clone());
        service
            .app_data(data.clone())
            .service(register)
            .service(resolve)
            .service(check_user)
            .service(announce)
            .service(sync)
            .service(list_nodes)
            .service(add_nodes)
            .service(envelope_pubkey)
            .service(envelope_pubkeys);
        #[cfg(feature = "pow")]
        if pow_enabled {
            service.service(pow_challenge);
        }
    }
}

#[post("/register")]
async fn register(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: Json<RegisterEnvelopeRequest>,
) -> RegistryResult<impl Responder> {
    let ip = peer_ip(&req, &state.trusted_proxies);
    state
        .rate_limiter
        .check(
            &ip.unwrap_or_else(|| "unknown".to_string()),
            RateScope::Register,
        )
        .await?;
    let handle = parse_user_id(&payload.handle)?;
    let now_ms = current_time_ms();
    let key = state
        .keys
        .find_by_kid(&payload.envelope.kid, now_ms)
        .ok_or_else(|| RegistryError::InvalidInput("unknown envelope key".to_string()))?;
    let identity = state
        .crypto
        .decrypt_identity(&payload.envelope, &key, &handle, now_ms)?;
    if identity.user_id != handle {
        return Err(RegistryError::InvalidInput(
            "handle does not match identity".to_string(),
        ));
    }
    state.store.register(identity).await?;
    Ok(HttpResponse::Ok().json(RegisterResponse { ok: true }))
}

#[post("/resolve")]
async fn resolve(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: Json<ResolveRequest>,
) -> RegistryResult<impl Responder> {
    let ip = peer_ip(&req, &state.trusted_proxies);
    state
        .rate_limiter
        .check(
            &ip.unwrap_or_else(|| "unknown".to_string()),
            RateScope::Resolve,
        )
        .await?;
    #[cfg(feature = "pow")]
    {
        state
            .pow
            .verify_header(
                req.headers()
                    .get("x-enigma-pow")
                    .and_then(|v| v.to_str().ok()),
            )
            .await?;
    }
    let handle = parse_user_id(&payload.handle)?;
    let requester_pubkey = parse_hex_array::<32>(
        &payload.requester_ephemeral_pubkey_hex,
        "requester_ephemeral_pubkey_hex",
    )?;
    let identity = state.store.resolve(&handle).await?;
    let now_ms = current_time_ms();
    let envelope = if let Some(identity) = identity {
        let key = state
            .keys
            .active_key(now_ms)
            .ok_or_else(|| RegistryError::Internal)?;
        Some(state.crypto.encrypt_identity_for_peer(
            &key,
            &handle,
            &identity,
            requester_pubkey,
            None,
            now_ms,
        )?)
    } else {
        None
    };
    Ok(HttpResponse::Ok().json(ResolveResponse {
        handle: payload.handle.clone(),
        envelope,
    }))
}

#[get("/check_user/{handle}")]
async fn check_user(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> RegistryResult<impl Responder> {
    let ip = peer_ip(&req, &state.trusted_proxies);
    state
        .rate_limiter
        .check(
            &ip.unwrap_or_else(|| "unknown".to_string()),
            RateScope::CheckUser,
        )
        .await?;
    #[cfg(feature = "pow")]
    {
        state
            .pow
            .verify_header(
                req.headers()
                    .get("x-enigma-pow")
                    .and_then(|v| v.to_str().ok()),
            )
            .await?;
    }
    let handle = parse_user_id(&path.into_inner())?;
    let exists = state.store.check_user(&handle).await?;
    Ok(HttpResponse::Ok().json(CheckUserResponse { exists }))
}

#[post("/announce")]
async fn announce(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: Json<Presence>,
) -> RegistryResult<impl Responder> {
    let ip = peer_ip(&req, &state.trusted_proxies);
    state
        .rate_limiter
        .check(
            &ip.unwrap_or_else(|| "unknown".to_string()),
            RateScope::Global,
        )
        .await?;
    state.store.announce(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(OkResponse { ok: true }))
}

#[post("/sync")]
async fn sync(
    state: web::Data<AppState>,
    req: HttpRequest,
    payload: Json<SyncRequest>,
) -> RegistryResult<impl Responder> {
    if !state.allow_sync {
        return Err(RegistryError::Unauthorized);
    }
    let ip = peer_ip(&req, &state.trusted_proxies);
    state
        .rate_limiter
        .check(
            &ip.unwrap_or_else(|| "unknown".to_string()),
            RateScope::Global,
        )
        .await?;
    let merged = state
        .store
        .sync_identities(payload.into_inner().identities)
        .await?;
    Ok(HttpResponse::Ok().json(SyncResponse { merged }))
}

#[get("/nodes")]
async fn list_nodes(state: web::Data<AppState>) -> RegistryResult<impl Responder> {
    let nodes = state.store.list_nodes().await?;
    Ok(HttpResponse::Ok().json(NodesPayload { nodes }))
}

#[post("/nodes")]
async fn add_nodes(
    state: web::Data<AppState>,
    payload: Json<NodesPayload>,
) -> RegistryResult<impl Responder> {
    let merged = state.store.add_nodes(payload.into_inner().nodes).await?;
    Ok(HttpResponse::Ok().json(MergedResponse { merged }))
}

#[get("/envelope_pubkey")]
async fn envelope_pubkey(state: web::Data<AppState>) -> RegistryResult<impl Responder> {
    let now_ms = current_time_ms();
    let key = state
        .keys
        .active_key(now_ms)
        .ok_or_else(|| RegistryError::Internal)?;
    let body = EnvelopePublicKey {
        kid_hex: hex::encode(key.kid),
        x25519_public_key_hex: hex::encode(key.public),
        active: key.active,
        not_after_epoch_ms: key.not_after,
    };
    Ok(HttpResponse::Ok().json(body))
}

#[get("/envelope_pubkeys")]
async fn envelope_pubkeys(state: web::Data<AppState>) -> RegistryResult<impl Responder> {
    let body = state.keys.public_keys();
    Ok(HttpResponse::Ok().json(body))
}

#[cfg(feature = "pow")]
#[get("/pow/challenge")]
async fn pow_challenge(state: web::Data<AppState>) -> RegistryResult<impl Responder> {
    if !state.pow.enabled() {
        return Err(RegistryError::FeatureDisabled("pow".to_string()));
    }
    let challenge: PowChallenge = state.pow.issue().await?;
    Ok(HttpResponse::Ok().json(challenge))
}

fn parse_user_id(input: &str) -> RegistryResult<UserId> {
    UserId::from_hex(input).map_err(|_| RegistryError::InvalidInput("handle".to_string()))
}

fn parse_hex_array<const N: usize>(value: &str, field: &str) -> RegistryResult<[u8; N]> {
    let bytes = hex::decode(value).map_err(|_| RegistryError::InvalidInput(field.to_string()))?;
    if bytes.len() != N {
        return Err(RegistryError::InvalidInput(field.to_string()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn peer_ip(req: &HttpRequest, trusted_proxies: &[String]) -> Option<String> {
    if let Some(header) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let parts: Vec<&str> = header.split(',').collect();
        for part in parts {
            let candidate = part.trim();
            if candidate.is_empty() {
                continue;
            }
            if trusted_proxies.iter().any(|p| p == candidate) {
                continue;
            }
            return Some(candidate.to_string());
        }
    }
    req.peer_addr().map(|addr| addr.ip().to_string())
}
