//! CLI glue for `pass quick-unlock` and for `pass unlock --pin`.

use crate::quickunlock::{self, OpenError, QuickUnlock, MAX_FAILURES, MIN_PIN_LENGTH};
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use crate::access::prompt_secret;
use dialoguer::{Confirm, Password};
use pass_agent::Client;
use passlib::Vault;
use std::io::IsTerminal;
use std::path::Path;
use std::time::Duration;

#[derive(Subcommand)]
pub enum QuickUnlockAction {
    /// Set up a PIN that can unlock this vault instead of the master password
    Enable {
        /// Command to run as a second factor before the PIN is accepted,
        /// e.g. `fprintd-verify` for a fingerprint reader. Must exit 0 only
        /// on success.
        #[arg(long, num_args = 1.., value_name = "COMMAND")]
        verify_command: Option<Vec<String>>,
    },
    /// Forget the PIN; unlocking needs the master password again
    Disable,
    /// Show whether quick unlock is set up, and for which vault
    Status,
}

pub fn cmd_quick_unlock(vault_path: &Path, action: QuickUnlockAction) -> Result<()> {
    let path = quickunlock::record_path()?;

    match action {
        QuickUnlockAction::Enable { verify_command } => enable(vault_path, &path, verify_command),
        QuickUnlockAction::Disable => disable(&path),
        QuickUnlockAction::Status => status(&path),
    }
}

fn enable(vault_path: &Path, record_path: &Path, verify_command: Option<Vec<String>>) -> Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("Vault file not found: {}", vault_path.display());
    }

    println!("{}", "🔓 Set up quick unlock".bold().cyan());
    println!();
    println!("Your master password will be sealed with this PIN and stored at");
    println!("  {}", record_path.display().to_string().bright_black());
    println!();

    let master_password = prompt_secret("Master password")?;

    // Verify before storing: sealing a wrong password would produce a PIN
    // that "works" and then fails to open the vault, with nothing to say why.
    Vault::unlock(vault_path, &master_password).context("Failed to unlock vault (wrong password?)")?;

    // Confirm only when there's a terminal to confirm on; piped input
    // supplies the PIN once, like `pass init` does with the master password.
    let pin = if std::io::stdin().is_terminal() {
        Password::new()
            .with_prompt(format!("New PIN (at least {MIN_PIN_LENGTH} characters)"))
            .with_confirmation("Confirm PIN", "PINs don't match")
            .interact()
            .context("Failed to read PIN")?
    } else {
        prompt_secret("PIN")?
    };

    if quickunlock::is_numeric_pin(&pin) {
        println!();
        println!(
            "{}",
            "⚠️  A digits-only PIN is guessable offline by anyone who copies the file."
                .yellow()
                .bold()
        );
        println!("   Mixing in letters costs you nothing and helps a lot.");
        println!();
        if !Confirm::new()
            .with_prompt("Use this PIN anyway?")
            .default(false)
            .interact()
            .context("Failed to read confirmation")?
        {
            println!("{}", "Cancelled.".yellow());
            return Ok(());
        }
    }

    // Fail now rather than at the first unlock, when the user has already
    // forgotten they configured it.
    if let Some(command) = &verify_command {
        println!();
        println!("Testing the verify command…");
        if !quickunlock::run_verify_command(command)? {
            anyhow::bail!(
                "The verify command exited non-zero. Fix it (or drop --verify-command) and try again."
            );
        }
        println!("{}", "  ✓ verify command succeeded".green());
    }

    let record = QuickUnlock::seal(vault_path, &master_password, &pin, verify_command)?;
    quickunlock::store(record_path, &record)?;

    println!();
    println!("{}", "✅ Quick unlock enabled.".green().bold());
    println!("   Unlock with {}.", "pass unlock --pin".cyan());
    println!("   After {MAX_FAILURES} wrong PINs it disables itself.");
    println!();

    Ok(())
}

fn disable(record_path: &Path) -> Result<()> {
    if quickunlock::load(record_path)?.is_none() {
        println!("{}", "Quick unlock is not enabled.".yellow());
        return Ok(());
    }

    quickunlock::remove(record_path)?;
    println!("{}", "✅ Quick unlock disabled.".green().bold());
    Ok(())
}

fn status(record_path: &Path) -> Result<()> {
    println!();
    match quickunlock::load(record_path)? {
        None => {
            println!("{}", "🔒 Quick unlock is not enabled.".yellow());
            println!("   Enable it with {}.", "pass quick-unlock enable".cyan());
        }
        Some(record) => {
            println!("{}", "🔓 Quick unlock is enabled".green().bold());
            println!("   Vault: {}", record.vault().display());
            println!("   Record: {}", record_path.display());
            match record.verify_command() {
                Some(command) => println!("   Second factor: {}", command.join(" ")),
                None => println!("   Second factor: {}", "none".bright_black()),
            }
            if record.failures() > 0 {
                println!(
                    "   {}",
                    format!(
                        "{} failed attempt(s); {} left before it disables itself",
                        record.failures(),
                        MAX_FAILURES.saturating_sub(record.failures())
                    )
                    .yellow()
                );
            }
        }
    }
    println!();

    Ok(())
}

/// `pass unlock --pin`: unlock the agent using the stored PIN record.
pub fn unlock_with_pin(vault_path: &Path, idle_minutes: Option<u64>) -> Result<()> {
    let record_path = quickunlock::record_path()?;
    let mut record = quickunlock::load(&record_path)?.ok_or_else(|| {
        anyhow::anyhow!("Quick unlock is not set up. Run `pass quick-unlock enable` first.")
    })?;

    if record.vault() != vault_path {
        anyhow::bail!(
            "Quick unlock is set up for {}, not {}.",
            record.vault().display(),
            vault_path.display()
        );
    }

    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    if !client.is_running() {
        anyhow::bail!("No agent is running. Start one with `pass agent run` first.");
    }

    if let Some(command) = record.verify_command().map(<[String]>::to_vec) {
        println!("{}", "Waiting for local authentication…".bright_black());
        if !quickunlock::run_verify_command(&command)? {
            anyhow::bail!("Local authentication failed.");
        }
    }

    let pin = prompt_secret("PIN")?;

    let master_password = match record.open(&pin) {
        Ok(password) => {
            // Persist the reset failure counter.
            quickunlock::store(&record_path, &record)?;
            password
        }
        Err(e) => {
            // Persist the *incremented* counter before reporting, so killing
            // the process mid-guess doesn't reset the budget.
            if record.is_burned() {
                quickunlock::remove(&record_path)?;
                anyhow::bail!(
                    "{e}\n\nQuick unlock has been disabled. Unlock with your master password \
                     (`pass unlock`) and set it up again."
                );
            }
            quickunlock::store(&record_path, &record)?;
            return Err(match e {
                OpenError::WrongPin { .. } => anyhow::anyhow!(e),
                other => anyhow::anyhow!(other),
            });
        }
    };

    let timeout = idle_minutes.map(|m| Duration::from_secs(m * 60));
    client
        .unlock(vault_path, &master_password, timeout)
        .map_err(|e| anyhow::anyhow!(e))?;

    let status = client.status().map_err(|e| anyhow::anyhow!(e))?;
    println!();
    println!("{}", "✅ Vault unlocked.".green().bold());
    println!("   SSH keys now served: {}", status.ssh_keys);
    println!();

    Ok(())
}
