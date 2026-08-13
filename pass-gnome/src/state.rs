use passlib::Vault;
use std::path::PathBuf;

/// Everything needed to operate on an unlocked vault: the vault itself
/// plus the master password, kept only in memory for the lifetime of the
/// unlock, needed again for every `save()` (the vault re-encrypts with a
/// fresh salt/nonce on every save).
pub struct Unlocked {
    pub vault: Vault,
    pub master_password: String,
}

/// Application state shared across the whole window via `Rc<RefCell<..>>`.
pub struct AppState {
    pub vault_path: PathBuf,
    pub unlocked: Option<Unlocked>,
}

impl AppState {
    pub fn new() -> Self {
        let default_path = dirs_home().join("passwords.kdbx");
        Self {
            vault_path: default_path,
            unlocked: None,
        }
    }
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}
