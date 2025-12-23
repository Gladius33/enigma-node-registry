use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

pub type RegistryResult<T> = Result<T, RegistryError>;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("rate limited")]
    RateLimited,
    #[error("pow required")]
    PowRequired,
    #[error("unauthorized")]
    Unauthorized,
    #[error("config error: {0}")]
    Config(String),
    #[error("feature disabled: {0}")]
    FeatureDisabled(String),
    #[error("internal error")]
    Internal,
}

impl RegistryError {
    pub fn with_details(self, details: Value) -> Self {
        match self {
            RegistryError::InvalidInput(msg) => {
                RegistryError::InvalidInput(format!("{}: {}", msg, details))
            }
            RegistryError::Config(msg) => RegistryError::Config(format!("{}: {}", msg, details)),
            other => other,
        }
    }
}

impl ResponseError for RegistryError {
    fn status_code(&self) -> StatusCode {
        match self {
            RegistryError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            RegistryError::Conflict => StatusCode::CONFLICT,
            RegistryError::NotFound => StatusCode::NOT_FOUND,
            RegistryError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            RegistryError::PowRequired => StatusCode::BAD_REQUEST,
            RegistryError::Unauthorized => StatusCode::UNAUTHORIZED,
            RegistryError::Config(_) => StatusCode::BAD_REQUEST,
            RegistryError::FeatureDisabled(_) => StatusCode::BAD_REQUEST,
            RegistryError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let code = match self {
            RegistryError::InvalidInput(_) => "INVALID_INPUT",
            RegistryError::Conflict => "CONFLICT",
            RegistryError::NotFound => "NOT_FOUND",
            RegistryError::RateLimited => "RATE_LIMITED",
            RegistryError::PowRequired => "POW_REQUIRED",
            RegistryError::Unauthorized => "UNAUTHORIZED",
            RegistryError::Config(_) => "CONFIG",
            RegistryError::FeatureDisabled(_) => "FEATURE_DISABLED",
            RegistryError::Internal => "INTERNAL",
        };
        let message = self.to_string();
        let body = ErrorResponse {
            error: ErrorBody {
                code: code.to_string(),
                message,
                details: None,
            },
        };
        HttpResponse::build(self.status_code()).json(body)
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(err: serde_json::Error) -> Self {
        RegistryError::InvalidInput(err.to_string())
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(err: std::io::Error) -> Self {
        RegistryError::Config(err.to_string())
    }
}

#[cfg(feature = "persistence")]
impl From<sled::Error> for RegistryError {
    fn from(err: sled::Error) -> Self {
        RegistryError::Internal.with_details(serde_json::json!({ "error": err.to_string() }))
    }
}
