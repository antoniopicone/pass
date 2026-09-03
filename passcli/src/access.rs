//! Getting at the vault, with or without an agent.
//!
//! Every command needs the same thing: an unlocked vault. There are two ways
//! to get one, and which is available depends on whether an agent happens to
//! be running, so the choice is made here once rather than in each command.
//!
//! - **Agent running and unlocked** — no prompt at all. This is what makes
//!   `pass` usable as something other than an interactive tool.
//! - **Otherwise** — prompt for the master password, exactly as before.
//!
//! Commands that only read one entry should prefer [`AgentOrPrompt::entry`],
//! which goes through the agent's own lookup and never materialises the whole
//! vault in this process.

use anyhow::{Context, Result};
use dialoguer::Password;
use pass_agent::Client;
use passlib::Vault;
use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

/// Ask for a secret, from the terminal when there is one and from stdin when
/// there isn't.
///
/// Without the stdin path, `pass unlock` could only ever be typed by hand:
/// no systemd unit, no `pass-askpass` helper, no script. The terminal path
/// stays the default so an interactive user never has their password echoed.
pub fn prompt_secret(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        return Password::new()
            .with_prompt(prompt)
            .interact()
            .with_context(|| format!("Failed to read {prompt}"));
    }

    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .with_context(|| format!("Failed to read {prompt} from stdin"))?;
    if read == 0 {
        anyhow::bail!("No {prompt} on stdin");
    }

    // Only the trailing newline: a password may legitimately end in a space.
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Resolves vault access for a single command invocation.
pub struct AgentOrPrompt {
    vault_path: PathBuf,
    client: Option<Client>,
}

impl AgentOrPrompt {
    pub fn new(vault_path: &Path) -> Self {
        // A client is only worth holding if something is actually listening;
        // `is_running` is one connect() and saves every later call from having
        // to distinguish "no agent" from "agent said no".
        let client = Client::with_default_path().ok().filter(Client::is_running);
        Self {
            vault_path: vault_path.to_path_buf(),
            client,
        }
    }

    /// The agent's client, if one is running.
    pub fn client(&self) -> Option<&Client> {
        self.client.as_ref()
    }

    /// Whether an agent is running *and* has this vault unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.client
            .as_ref()
            .and_then(|c| c.status().ok())
            .is_some_and(|s| s.unlocked)
    }

    /// Open the vault, using the agent's held master password when possible
    /// and prompting otherwise.
    ///
    /// Returns the password alongside the vault because saving re-encrypts,
    /// and a caller that modified the vault needs it.
    pub fn open(&self) -> Result<(Vault, String)> {
        let password = self.master_password()?;
        let vault = Vault::unlock(&self.vault_path, &password)
            .context("Failed to unlock vault (wrong password?)")?;
        Ok((vault, password))
    }

    /// Read one entry, preferring the agent so no password is typed and no
    /// full vault is decrypted in this process.
    pub fn entry(&self, query: &str) -> Result<pass_agent::protocol::Entry> {
        if let Some(client) = self.client.as_ref() {
            if let Ok(entry) = client.get_entry(query) {
                return Ok(entry);
            }
            // Fall through on failure: the agent may simply be locked, and a
            // prompt is a better answer than an error.
        }

        let (vault, _) = self.open()?;
        let entry = crate::find_entry(&vault, query)?;
        Ok(pass_agent::protocol::Entry::from(&entry))
    }

    /// The master password: the agent's if it has one, otherwise typed.
    ///
    /// The agent deliberately never hands the master password back over the
    /// socket — it would turn every client into a place the password can leak
    /// from. So when the agent is unlocked but this command needs to *write*
    /// to the vault, we still prompt.
    fn master_password(&self) -> Result<String> {
        prompt_secret("Master password")
    }


    /// Tell a running agent to re-read its SSH keys, after a command changed
    /// them. Best-effort: a command that succeeded must not fail because the
    /// agent was not listening.
    pub fn notify_ssh_keys_changed(&self) {
        if let Some(client) = self.client.as_ref() {
            let _ = client.reload_ssh_keys();
        }
    }
}
