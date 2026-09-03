//! `pass ssh` — SSH keys living in the vault instead of in `~/.ssh`.
//!
//! The point of keeping keys here is that `~/.ssh/id_ed25519` is a plaintext
//! private key sitting on disk, readable by anything running as you, backed
//! up to wherever your home directory is backed up. In the vault it is
//! encrypted at rest with everything else, syncs with everything else, and is
//! only ever exposed through the agent, which hands out *signatures* and
//! never the key.

use crate::access::AgentOrPrompt;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use dialoguer::{Confirm, Password};
use passlib::SshKey;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum SshAction {
    /// Generate a new Ed25519 key straight into the vault
    Generate {
        /// Name to file the key under
        name: String,
        /// Key comment (defaults to user@host)
        #[arg(long)]
        comment: Option<String>,
    },
    /// Import an existing private key file into the vault
    Import {
        /// Path to the OpenSSH private key (e.g. ~/.ssh/id_ed25519)
        file: PathBuf,
        /// Name to file the key under (defaults to the file name)
        #[arg(long)]
        name: Option<String>,
    },
    /// List the SSH keys in the vault
    List,
    /// Print a key's public half, ready for authorized_keys
    Pub {
        /// Key name, id, or fingerprint
        query: String,
    },
    /// Remove a key from the vault
    Rm {
        /// Key name, id, or fingerprint
        query: String,
    },
    /// Write a key's private half out to a file (last resort — this undoes
    /// the reason for storing it in the vault)
    Export {
        /// Key name, id, or fingerprint
        query: String,
        /// Where to write it
        #[arg(long)]
        out: PathBuf,
    },
}

pub fn cmd_ssh(vault_path: &Path, action: SshAction) -> Result<()> {
    let access = AgentOrPrompt::new(vault_path);

    match action {
        SshAction::Generate { name, comment } => generate(&access, &name, comment),
        SshAction::Import { file, name } => import(&access, &file, name),
        SshAction::List => list(&access),
        SshAction::Pub { query } => print_public(&access, &query),
        SshAction::Rm { query } => remove(&access, &query),
        SshAction::Export { query, out } => export(&access, &query, &out),
    }
}

fn generate(access: &AgentOrPrompt, name: &str, comment: Option<String>) -> Result<()> {
    let comment = comment.unwrap_or_else(default_comment);
    let key = SshKey::generate(name, &comment).context("Failed to generate SSH key")?;

    let (mut vault, password) = access.open()?;
    vault.add_ssh_key(&key).context("Failed to store the key in the vault")?;
    vault.save(&password).context("Failed to save vault")?;
    access.notify_ssh_keys_changed();

    println!();
    println!("{}", format!("✅ Generated '{name}'.").green().bold());
    println!("   {}: {}", "Fingerprint".bold(), key.fingerprint);
    println!();
    println!("   Public key (add this to the server's authorized_keys):");
    println!("   {}", key.public_key.cyan());
    println!();
    print_agent_hint(access);

    Ok(())
}

fn import(access: &AgentOrPrompt, file: &Path, name: Option<String>) -> Result<()> {
    let pem = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read {}", file.display()))?;

    let name = name.unwrap_or_else(|| {
        file.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "imported key".to_string())
    });

    // Only ask for a passphrase if the key actually has one — most don't, and
    // an unconditional prompt trains people to type their master password
    // into whatever asks.
    let key = match SshKey::import_openssh(&name, &pem, None) {
        Ok(key) => key,
        Err(passlib::PassError::SshKey(message)) if message.contains("passphrase-protected") => {
            let passphrase = Password::new()
                .with_prompt(format!("Passphrase for {}", file.display()))
                .interact()
                .context("Failed to read key passphrase")?;
            SshKey::import_openssh(&name, &pem, Some(&passphrase)).context("Failed to import key")?
        }
        Err(e) => return Err(e).context("Failed to import key"),
    };

    let (mut vault, password) = access.open()?;
    vault.add_ssh_key(&key).context("Failed to store the key in the vault")?;
    vault.save(&password).context("Failed to save vault")?;
    access.notify_ssh_keys_changed();

    println!();
    println!("{}", format!("✅ Imported '{name}'.").green().bold());
    println!("   {}: {}", "Fingerprint".bold(), key.fingerprint);
    println!();
    println!(
        "   {} the key is still on disk at {}. Once you've confirmed the",
        "Next:".yellow().bold(),
        file.display()
    );
    println!("   agent works, delete it (and its .pub) — leaving it there keeps");
    println!("   the plaintext copy this was meant to remove.");
    println!();
    print_agent_hint(access);

    Ok(())
}

fn list(access: &AgentOrPrompt) -> Result<()> {
    // Prefer the agent: it already has the keys loaded and needs no password.
    let keys = match access.client().filter(|_| access.is_unlocked()) {
        Some(client) => client.list_ssh_keys().map_err(|e| anyhow::anyhow!(e))?,
        None => access.open()?.0.list_ssh_keys()?,
    };

    println!();
    if keys.is_empty() {
        println!("{}", "No SSH keys in this vault.".yellow());
        println!("Add one with {}.", "pass ssh generate <name>".cyan());
        println!();
        return Ok(());
    }

    println!("{}", format!("🔑 SSH Keys ({})", keys.len()).bold().cyan());
    println!();
    for key in &keys {
        println!("{}", "─".repeat(60).bright_black());
        println!("{}: {}", "Name".bold(), key.name);
        println!("{}: {}", "Type".bold(), key.algorithm);
        println!("{}: {}", "Fingerprint".bold(), key.fingerprint);
        if !key.comment.is_empty() {
            println!("{}: {}", "Comment".bright_black(), key.comment.bright_black());
        }
        println!("{}: {}", "ID".bright_black(), key.id.bright_black());
    }
    println!("{}", "─".repeat(60).bright_black());
    println!();

    Ok(())
}

fn print_public(access: &AgentOrPrompt, query: &str) -> Result<()> {
    // Bare output, no decoration: this is meant to be piped or copied.
    if let Some(client) = access.client().filter(|_| access.is_unlocked()) {
        if let Ok(keys) = client.list_ssh_keys() {
            if let Some(key) = keys.iter().find(|k| matches_key(&k.id, &k.name, &k.fingerprint, query)) {
                println!("{}", key.public_key);
                return Ok(());
            }
        }
    }

    let (vault, _) = access.open()?;
    let key = vault.get_ssh_key(query).with_context(|| format!("SSH key not found: {query}"))?;
    println!("{}", key.public_key);
    Ok(())
}

fn remove(access: &AgentOrPrompt, query: &str) -> Result<()> {
    let (mut vault, password) = access.open()?;
    let key = vault.get_ssh_key(query).with_context(|| format!("SSH key not found: {query}"))?;

    println!();
    println!("About to remove:");
    println!("  Name: {}", key.name);
    println!("  Fingerprint: {}", key.fingerprint);
    println!();
    println!(
        "{}",
        "This is the only copy unless you exported it. Anything trusting this key will stop working."
            .yellow()
    );
    println!();

    if !Confirm::new()
        .with_prompt("Remove this key?")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?
    {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }

    vault.delete_ssh_key(&key.id).context("Failed to remove the key")?;
    vault.save(&password).context("Failed to save vault")?;
    access.notify_ssh_keys_changed();

    println!("{}", "✅ Key removed (recoverable from the Recycle Bin).".green().bold());
    Ok(())
}

fn export(access: &AgentOrPrompt, query: &str, out: &Path) -> Result<()> {
    if out.exists() {
        anyhow::bail!("Refusing to overwrite {}", out.display());
    }

    let (vault, _) = access.open()?;
    let key = vault.get_ssh_key(query).with_context(|| format!("SSH key not found: {query}"))?;

    println!();
    println!(
        "{}",
        "⚠️  This writes an unencrypted private key to disk — the thing keeping it in the vault avoided."
            .yellow()
            .bold()
    );
    println!("   Only do this for a tool that cannot use an SSH agent.");
    println!();
    if !Confirm::new()
        .with_prompt(format!("Write '{}' to {}?", key.name, out.display()))
        .default(false)
        .interact()
        .context("Failed to read confirmation")?
    {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }

    let pem = key.private_key_pem()?;
    write_private_key(out, pem.as_slice())?;

    println!();
    println!("{}", format!("✅ Written to {} (mode 0600).", out.display()).green().bold());
    Ok(())
}

/// Write a private key with owner-only permissions, and create it that way
/// rather than fixing the mode afterwards — between `create` and `chmod`
/// there is a window where the key is world-readable, and `ssh` would refuse
/// the file anyway.
fn write_private_key(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    file.sync_all()?;
    Ok(())
}

fn matches_key(id: &str, name: &str, fingerprint: &str, query: &str) -> bool {
    id == query || fingerprint == query || name.eq_ignore_ascii_case(query)
}

fn default_comment() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string());
    let host = hostname().unwrap_or_else(|| "host".to_string());
    format!("{user}@{host}")
}

fn hostname() -> Option<String> {
    // `/etc/hostname` and `$HOSTNAME` cover Linux and most shells without
    // pulling in a crate for one string.
    std::env::var("HOSTNAME").ok().or_else(|| {
        std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    })
}

fn print_agent_hint(access: &AgentOrPrompt) {
    if access.is_unlocked() {
        println!("   The agent has picked it up — {} will show it.", "ssh-add -l".cyan());
    } else {
        println!(
            "   Start the agent and unlock it ({} then {}) to use this key.",
            "pass agent run".cyan(),
            "pass unlock".cyan()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_matching_accepts_id_name_and_fingerprint() {
        let id = "1234-5678";
        let name = "Work Laptop";
        let fingerprint = "SHA256:abcdef";

        assert!(matches_key(id, name, fingerprint, id));
        assert!(matches_key(id, name, fingerprint, fingerprint));
        assert!(matches_key(id, name, fingerprint, "work laptop"));
        assert!(!matches_key(id, name, fingerprint, "something else"));
    }

    #[test]
    fn default_comment_looks_like_ssh_keygens() {
        let comment = default_comment();
        assert!(comment.contains('@'), "expected user@host, got {comment}");
        assert!(!comment.starts_with('@'), "empty user in {comment}");
        assert!(!comment.ends_with('@'), "empty host in {comment}");
    }

    #[test]
    fn exported_keys_are_owner_only_and_never_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ed25519");

        write_private_key(&path, b"-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        assert!(path.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "exported key is not 0600");
        }

        // Never clobber an existing key file.
        assert!(write_private_key(&path, b"other").is_err());
    }
}
