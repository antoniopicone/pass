//! # PassLib - Secure Password Manager Library
//!
//! A password management library storing vaults as real KDBX4 databases
//! (KeePass/KeePassXC's native format, via the `keepass` crate), so a
//! vault written here opens directly in KeePassXC and vice versa.
//!
//! ## Features
//!
//! - **KDBX4 storage**: AES-256 + Argon2id, the same construction KeePassXC uses
//! - **Zero-Knowledge**: Master password never stored, no recovery mechanism
//! - **Memory Safety**: Automatic zeroization of sensitive data
//! - **Cross-device merge**: reconciles two independently-edited copies of
//!   a vault using KDBX's own last-modification timestamps
//! - **MFA/TOTP**: codes generated from the same `otp` field KeePassXC writes
//!
//! ## Example
//!
//! ```no_run
//! use passlib::{Vault, PasswordEntry};
//!
//! // Create a new vault
//! let mut vault = Vault::init("passwords.kdbx", "my_master_password").unwrap();
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
//! let vault = Vault::unlock("passwords.kdbx", "my_master_password").unwrap();
//! let entries = vault.list_entries().unwrap();
//! ```

pub mod entry;
pub mod error;
pub mod generator;
pub mod secmem;
pub mod share;
pub mod sshkey;
pub mod sync;
pub mod totp;
pub mod vault;

// Re-export main types
pub use entry::{PasswordEntry, PasswordEntrySummary};
pub use error::{PassError, Result};
pub use generator::{generate_password, GeneratorOptions};
pub use secmem::{SecretBuf, Shielded};
pub use share::{ShareBundle, ShareIdentity, SharedEntry};
pub use sshkey::{SshKey, SshKeySummary};
pub use sync::{DeviceIdentity, SyncEntry, SyncKey};
pub use totp::{TotpAlgorithm, TotpConfig};
pub use vault::{MergeSummary, ShareContact, SyncDevice, Vault};
