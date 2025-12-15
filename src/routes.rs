use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use enigma_node_types::{
    CheckUserResponse, NodesPayload, Presence, RegisterRequest, RegisterResponse, ResolveResponse,
    SyncRequest, SyncResponse, UserId,
};
use serde::{Deserialize, Serialize};

use crate::error::{EnigmaNodeRegistryError, Result};
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OkResponse {
    ok: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MergedResponse {
    merged: usize,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn build_router(state: AppState) -> axum::Router {
    axum::Router::new()
        .route("/register", post(register))
        .route("/resolve/:user_id_hex", get(resolve))
        .route("/check_user/:user_id_hex", get(check_user))
        .route("/announce", post(announce))
        .route("/sync", post(sync))
        .route("/nodes", get(list_nodes).post(add_nodes))
        .with_state(state)
}

async fn register(
    State(state): State<AppState>,
    payload: std::result::Result<Json<RegisterRequest>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let Json(body) = payload?;
    state.store.register(body.identity).await?;
    Ok((StatusCode::OK, Json(RegisterResponse { ok: true })))
}

async fn resolve(
    State(state): State<AppState>,
    Path(user_id_hex): Path<String>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let user_id = parse_user_id(&user_id_hex)?;
    let identity = state.store.resolve(&user_id).await?;
    Ok((StatusCode::OK, Json(ResolveResponse { identity })))
}

async fn check_user(
    State(state): State<AppState>,
    Path(user_id_hex): Path<String>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let user_id = parse_user_id(&user_id_hex)?;
    let exists = state.store.check_user(&user_id).await?;
    Ok((StatusCode::OK, Json(CheckUserResponse { exists })))
}

async fn announce(
    State(state): State<AppState>,
    payload: std::result::Result<Json<Presence>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let Json(body) = payload?;
    state.store.announce(body).await?;
    Ok((StatusCode::OK, Json(OkResponse { ok: true })))
}

async fn sync(
    State(state): State<AppState>,
    payload: std::result::Result<Json<SyncRequest>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let Json(body) = payload?;
    let merged = state.store.sync_identities(body.identities).await?;
    Ok((StatusCode::OK, Json(SyncResponse { merged })))
}

async fn list_nodes(
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let nodes = state.store.list_nodes().await?;
    Ok((StatusCode::OK, Json(NodesPayload { nodes })))
}

async fn add_nodes(
    State(state): State<AppState>,
    payload: std::result::Result<Json<NodesPayload>, axum::extract::rejection::JsonRejection>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let Json(body) = payload?;
    let merged = state.store.add_nodes(body.nodes).await?;
    Ok((StatusCode::OK, Json(MergedResponse { merged })))
}

fn parse_user_id(user_id_hex: &str) -> Result<UserId> {
    UserId::from_hex(user_id_hex).map_err(|_| EnigmaNodeRegistryError::InvalidInput("user_id"))
}

#[derive(Debug)]
pub struct AppError(pub EnigmaNodeRegistryError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            EnigmaNodeRegistryError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            EnigmaNodeRegistryError::JsonError => StatusCode::BAD_REQUEST,
            EnigmaNodeRegistryError::Conflict => StatusCode::CONFLICT,
            EnigmaNodeRegistryError::NotFound => StatusCode::NOT_FOUND,
            EnigmaNodeRegistryError::Transport => StatusCode::BAD_GATEWAY,
            EnigmaNodeRegistryError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(ErrorBody {
            error: self.0.to_string(),
        });
        (status, body).into_response()
    }
}

impl From<EnigmaNodeRegistryError> for AppError {
    fn from(err: EnigmaNodeRegistryError) -> Self {
        AppError(err)
    }
}

impl From<axum::extract::rejection::JsonRejection> for AppError {
    fn from(_: axum::extract::rejection::JsonRejection) -> Self {
        AppError(EnigmaNodeRegistryError::JsonError)
    }
}
