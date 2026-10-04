//! Remembers the last vault successfully unlocked or created, so every
//! client (CLI, GNOME, and — via `pass-native-host` — the Chromium
//! extension) can propose it back next time instead of a fixed default
//! every single time. Persisted at `$XDG_CONFIG_HOME/pass/last-vault` (or
//! `~/.config/pass/last-vault`), just the path as plain text — no need for
//! anything richer than that.
//!
//! On macOS the default vault lives in the App Group container Pass.app
//! shares with its AutoFill extension (see [`app_group_container`]), so
//! the app, the extension, the CLI and the Chromium native host all open
//! the same file.

use crate::error::{PassError, Result};
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

fn home_dir() -> PathBuf {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
}

/// File name of the default vault, both in `~/.vaults/` and in the App
/// Group container.
const DEFAULT_VAULT_FILE_NAME: &str = "personal.kdbx";

/// The App Group identifier Pass.app shares with its AutoFill extension on
/// macOS: `<TEAM_ID>.it.antoniopicone.Pass`. The Team ID isn't known to
/// this repo, so it comes from the build — `PASS_APP_GROUP` at compile
/// time (the Xcode build phase that bundles the CLI and native host into
/// Pass.app sets it from `DEVELOPMENT_TEAM`, see pass-apple/README.md) —
/// or from a `PASS_APP_GROUP` environment variable at run time, which
/// wins. `None` off macOS, or when neither is set.
pub fn app_group_id() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    std::env::var("PASS_APP_GROUP")
        .ok()
        .or_else(|| option_env!("PASS_APP_GROUP").map(String::from))
        .filter(|id| !id.trim().is_empty())
}

/// `~/Library/Group Containers/<app group>`, the directory macOS gives
/// Pass.app and its AutoFill extension (see [`app_group_id`]). Computed
/// rather than asked of the OS (`containerURL(forSecurityApplicationGroupIdentifier:)`
/// isn't reachable from Rust); it's the same path for any process of the
/// user. Since macOS 15 only processes signed by the same team can open it
/// without a consent prompt — hence bundling the CLI/native host into
/// Pass.app and signing them with it.
pub fn app_group_container() -> Option<PathBuf> {
    app_group_id().map(|id| group_container_in(&home_dir(), &id))
}

fn group_container_in(home: &Path, group_id: &str) -> PathBuf {
    home.join("Library").join("Group Containers").join(group_id)
}

/// Proposed path for a brand-new vault when nothing else is known yet: on
/// macOS builds that know the App Group, `personal.kdbx` in
/// [`app_group_container`] — reachable by the AutoFill extension —
/// otherwise `~/.vaults/personal.kdbx`. A fixed, predictable location
/// beats a cwd-relative one (the previous default, `passwords.kdbx`),
/// which silently meant "a different vault" depending on where a command
/// happened to be run from.
pub fn default_vault_path() -> PathBuf {
    match app_group_container() {
        Some(container) => container.join(DEFAULT_VAULT_FILE_NAME),
        None => home_dir().join(".vaults").join(DEFAULT_VAULT_FILE_NAME),
    }
}

/// Moves the vault at `from` to `to` — e.g. from `~/.vaults/` into the App
/// Group container so the AutoFill extension can read it — together with
/// its `pass-syncd` state file, and remembers `to` as the last vault so the
/// CLI and the Chromium native host follow it. Refuses to overwrite an
/// existing file at `to`. Callers must not keep a [`crate::Vault`] open on
/// `from` across this call: it would keep saving to the old path.
pub fn relocate_vault(from: &Path, to: &Path) -> Result<()> {
    if !from.exists() {
        return Err(PassError::VaultNotFound(from.display().to_string()));
    }
    if to.exists() {
        return Err(PassError::SaveError(format!("A vault already exists at {}", to.display())));
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    move_file(from, to)?;

    let (state_from, state_to) = (crate::sync::state_path(from), crate::sync::state_path(to));
    if state_from.exists() {
        // Losing the sync state only costs one full re-sync, so this is
        // best-effort rather than failing a move that already happened.
        let _ = move_file(&state_from, &state_to);
    }

    remember_last_vault(to);
    Ok(())
}

/// `rename`, falling back to copy + delete across volumes.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    std::fs::copy(from, to)?;
    std::fs::File::open(to)?.sync_all()?;
    std::fs::remove_file(from)
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

    #[test]
    fn group_container_path() {
        assert_eq!(
            group_container_in(Path::new("/Users/me"), "ABCDE12345.it.antoniopicone.Pass"),
            PathBuf::from("/Users/me/Library/Group Containers/ABCDE12345.it.antoniopicone.Pass")
        );
    }

    #[test]
    fn relocate_moves_vault_and_sync_state_and_remembers_it() {
        let _guard = ENV_LOCK.lock().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        std::env::set_var("XDG_CONFIG_HOME", scratch.path());

        let from = scratch.path().join("old").join("personal.kdbx");
        std::fs::create_dir_all(from.parent().unwrap()).unwrap();
        std::fs::write(&from, b"vault").unwrap();
        std::fs::write(crate::sync::state_path(&from), b"{}").unwrap();
        let to = scratch.path().join("Group Containers").join("X.it.antoniopicone.Pass").join("personal.kdbx");

        relocate_vault(&from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(std::fs::read(&to).unwrap(), b"vault");
        assert!(crate::sync::state_path(&to).exists());
        assert_eq!(last_vault().as_deref(), Some(to.as_path()));

        // Never overwrites an existing vault.
        std::fs::write(&from, b"other").unwrap();
        assert!(relocate_vault(&from, &to).is_err());
        assert_eq!(std::fs::read(&to).unwrap(), b"vault");

        std::env::remove_var("XDG_CONFIG_HOME");
    }
}
