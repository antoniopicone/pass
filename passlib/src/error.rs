use thiserror::Error;

#[derive(Error, Debug)]
pub enum PassError {
    #[error("Invalid master password")]
    InvalidPassword,

    #[error("Vault file not found: {0}")]
    VaultNotFound(String),

    #[error("Failed to read vault file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Vault is corrupted, tampered with, or not a valid KDBX4 file: {0}")]
    VaultCorrupted(String),

    #[error("Failed to save vault: {0}")]
    SaveError(String),

    #[error("Failed to merge vaults: {0}")]
    MergeError(String),

    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    #[error("TOTP error: {0}")]
    TotpError(String),
}

pub type Result<T> = std::result::Result<T, PassError>;
