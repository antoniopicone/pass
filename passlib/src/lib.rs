//! # PassLib - Secure Password Manager Library
//!
//! A cryptographically secure password management library using AES-256-GCM encryption
//! and Argon2id key derivation.
//!
//! ## Features
//!
//! - **Strong Encryption**: AES-256-GCM with authenticated encryption
//! - **Secure Key Derivation**: Argon2id (memory-hard, GPU-resistant)
//! - **Zero-Knowledge**: Master password never stored, no recovery mechanism
//! - **Memory Safety**: Automatic zeroization of sensitive data
//!
//! ## Example
//!
//! ```no_run
//! use passlib::{Vault, PasswordEntry};
//!
//! // Create a new vault
//! let mut vault = Vault::init("passwords.vault", "my_master_password").unwrap();
//!
//! // Add a password
//! let entry = PasswordEntry::new(
//!     "GitHub".to_string(),
//!     "https://github.com/login".to_string(),
//!     "user@example.com".to_string(),
//!     "secret_password".to_string(),
//! );
//! vault.add_entry(entry).unwrap();
//! vault.save("my_master_password").unwrap();
//!
//! // Later: unlock and access
//! let vault = Vault::unlock("passwords.vault", "my_master_password").unwrap();
//! let entries = vault.list_entries().unwrap();
//! ```

pub mod crypto;
pub mod entry;
pub mod error;
pub mod merge;
pub mod vault;

// Re-export main types
pub use entry::{PasswordEntry, PasswordEntrySummary};
pub use error::{PassError, Result};
pub use merge::MergeSummary;
pub use vault::Vault;
