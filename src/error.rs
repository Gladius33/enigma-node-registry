use enigma_node_types::EnigmaNodeTypesError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnigmaNodeRegistryError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnigmaNodeRegistryError {
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("json error")]
    JsonError,
    #[error("internal error")]
    Internal,
    #[error("transport error")]
    Transport,
}

impl From<serde_json::Error> for EnigmaNodeRegistryError {
    fn from(_: serde_json::Error) -> Self {
        EnigmaNodeRegistryError::JsonError
    }
}

impl From<EnigmaNodeTypesError> for EnigmaNodeRegistryError {
    fn from(err: EnigmaNodeTypesError) -> Self {
        match err {
            EnigmaNodeTypesError::InvalidUsername => {
                EnigmaNodeRegistryError::InvalidInput("username")
            }
            EnigmaNodeTypesError::InvalidHex => EnigmaNodeRegistryError::InvalidInput("user_id"),
            EnigmaNodeTypesError::InvalidBase64 => EnigmaNodeRegistryError::InvalidInput("base64"),
            EnigmaNodeTypesError::InvalidField(field) => {
                EnigmaNodeRegistryError::InvalidInput(field)
            }
            EnigmaNodeTypesError::JsonError => EnigmaNodeRegistryError::JsonError,
            EnigmaNodeTypesError::Utf8Error => EnigmaNodeRegistryError::InvalidInput("utf8"),
        }
    }
}

impl From<std::io::Error> for EnigmaNodeRegistryError {
    fn from(_: std::io::Error) -> Self {
        EnigmaNodeRegistryError::Transport
    }
}
