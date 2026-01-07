use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassError {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Vault file not found: {0}")]
    VaultNotFound(String),

    #[error("Failed to read vault file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to serialize/deserialize data: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Vault is corrupted or tampered with")]
    VaultCorrupted,

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("Invalid vault format or version")]
    InvalidVaultFormat,
}

pub type Result<T> = std::result::Result<T, PassError>;
