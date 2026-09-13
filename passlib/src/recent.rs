//! Remembers the last vault successfully unlocked or created, so every
//! client (CLI, GNOME, and — via `pass-native-host` — the Chromium
//! extension) can propose it back next time instead of a fixed default
//! every single time. Persisted at `$XDG_CONFIG_HOME/pass/last-vault` (or
//! `~/.config/pass/last-vault`), just the path as plain text — no need for
//! anything richer than that.

use std::path::{Path, PathBuf};

fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("pass");
        }
    }
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("pass")
}

fn last_vault_file() -> PathBuf {
    config_dir().join("last-vault")
}

/// Records `path` as the most recently used vault. Best-effort: a failure
/// to persist this (read-only home directory, etc.) should never turn a
/// successful unlock/init into an error, so this has no `Result` to check.
pub fn remember_last_vault(path: &Path) {
    if std::fs::create_dir_all(config_dir()).is_ok() {
        let _ = std::fs::write(last_vault_file(), path.to_string_lossy().as_bytes());
    }
}

/// The last vault path recorded by [`remember_last_vault`], if any and if
/// it's non-empty. Doesn't check whether the file still exists on disk —
/// see [`propose_vault_path`], which does.
pub fn last_vault() -> Option<PathBuf> {
    let contents = std::fs::read_to_string(last_vault_file()).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Proposed path for a brand-new vault when nothing else is known yet:
/// `~/.vaults/personal.kdbx`. A fixed, predictable location beats a
/// cwd-relative one (the previous default, `passwords.kdbx`), which
/// silently meant "a different vault" depending on where a command
/// happened to be run from.
pub fn default_vault_path() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".vaults").join("personal.kdbx")
}

/// The vault path to propose when the caller hasn't specified one: the
/// last one successfully unlocked/created, if it still exists on disk,
/// otherwise [`default_vault_path`] (which may not exist yet — callers
/// already handle a missing vault file fine, whether that means offering
/// to create one or failing with a clear "not found").
pub fn propose_vault_path() -> PathBuf {
    last_vault().filter(|p| p.exists()).unwrap_or_else(default_vault_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests in this module: `remember_last_vault`/`last_vault`
    /// share one file keyed off `$XDG_CONFIG_HOME`/`$HOME`, which is
    /// process-global state, so tests that point it at a scratch directory
    /// must not run concurrently with each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn remember_and_recall_roundtrip_and_propose_falls_back_when_gone() {
        let _guard = ENV_LOCK.lock().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", scratch.path());

        assert_eq!(last_vault(), None);

        let vault_path = scratch.path().join("some-vault.kdbx");
        std::fs::write(&vault_path, b"not a real vault, just needs to exist").unwrap();
        remember_last_vault(&vault_path);
        assert_eq!(last_vault().as_deref(), Some(vault_path.as_path()));
        assert_eq!(propose_vault_path(), vault_path);

        // The remembered path no longer exists on disk: propose falls back
        // to the fixed default rather than a dangling path.
        std::fs::remove_file(&vault_path).unwrap();
        assert_eq!(propose_vault_path(), default_vault_path());

        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
