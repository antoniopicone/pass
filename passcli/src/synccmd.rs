//! `pass sync` — replicate a vault between your own devices, with no server.
//!
//! The transport that already exists (`pass watch` over Syncthing/Nextcloud)
//! puts the encrypted file through somebody else's machine and needs that
//! service to be working. This one does not: devices that can reach each
//! other talk directly, and nothing else has to be running.
//!
//! What that costs is a pairing step. A device is allowed to write into
//! another's vault only if it is on that vault's roster, which the user puts
//! it on by hand — see [`SyncAction::Trust`]. Trusting whoever shows up would
//! mean any machine that can reach the port gets to change your passwords.
//!
//! See `docs/SYNC_STRATEGY.md` for how this fits with the other transports,
//! and [`passlib::sync`] for the merge rule.

use crate::access::AgentOrPrompt;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use pass_agent::Client;
use passlib::sync::crypto;
use std::path::Path;

#[derive(Subcommand)]
pub enum SyncAction {
    /// Show what the running agent's sync node is doing
    Status,
    /// Reconcile with every known peer now, instead of waiting for the next
    /// round
    Now,
    /// List the devices allowed to write into this vault
    Devices,
    /// Print this device's own sync key, to read out on another device
    Id,
    /// Allow a device to write into this vault
    Trust {
        /// Name to remember it by
        label: String,
        /// Its `pass-device-pk1:…` key, from `pass sync id` on that device
        public_key: String,
    },
    /// Stop accepting changes from a device
    ///
    /// This does not take back anything it has already read: without a
    /// server there is no such thing, and the honest answer to a lost device
    /// is to change the passwords on it.
    Forget {
        /// Its label or fingerprint
        device: String,
    },
}

pub fn cmd_sync(vault_path: &Path, action: SyncAction) -> Result<()> {
    match action {
        SyncAction::Status => status(),
        SyncAction::Now => now(),
        SyncAction::Devices => devices(vault_path),
        SyncAction::Id => id(vault_path),
        SyncAction::Trust { label, public_key } => trust(vault_path, &label, &public_key),
        SyncAction::Forget { device } => forget(vault_path, &device),
    }
}

fn status() -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    if !client.is_running() {
        println!("{}", "🔒 No agent running.".yellow());
        println!("   Start one with {}.", "pass agent run --sync".cyan());
        return Ok(());
    }

    let status = client.sync_status().map_err(|e| anyhow::anyhow!(e))?;

    if status.device.is_empty() {
        println!("{}", "🔗 Sync is on, but this vault has never been unlocked.".yellow());
        println!("   Run {} — the device cannot sign anything until then.", "pass unlock".cyan());
        return Ok(());
    }

    println!("{}", "🔗 Syncing".green().bold());
    println!("   This device: {} ({})", status.hostname.bold(), status.device.dimmed());
    println!("   Listening on: {}", status.listening_on);
    if status.advertise.is_empty() {
        println!("   {}", "Not announcing an address — this device calls out, nobody calls in.".dimmed());
    } else {
        println!("   Announcing: {}", status.advertise);
    }
    println!(
        "   Replicating: {} entries, {} ops, {} trusted device(s)",
        status.entries, status.ops, status.trusted_devices
    );
    // The one number worth comparing between two devices: equal means they
    // merged the same way, and a difference is a merge problem rather than a
    // network one.
    println!("   Fingerprint: {}", status.fingerprint.cyan());
    if status.pending_vault_write {
        println!("   {}", "Changes from peers are waiting for the vault to be unlocked.".yellow());
    }

    println!();
    if status.peers.is_empty() {
        println!("   {}", "No peers known yet.".dimmed());
    } else {
        println!("   {}", "Peers".bold());
        for peer in &status.peers {
            println!("     {} {}", peer.hostname.bold(), peer.addr.dimmed());
        }
    }

    if !status.log.is_empty() {
        println!();
        println!("   {}", "Recent activity".bold());
        for line in status.log.iter().take(10) {
            println!("     {}", line.dimmed());
        }
    }

    Ok(())
}

fn now() -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    client.sync_now().map_err(|e| anyhow::anyhow!(e))?;

    println!("{}", "🔄 Reconciling with known peers…".cyan());
    println!("   Watch it with {}.", "pass sync status".cyan());
    Ok(())
}

/// Which device the running agent believes it is.
///
/// The vault alone cannot answer this. A second device is set up by copying
/// the vault file, so the copy contains the *first* device's signing key as
/// well as its own — "the entry that has a private key" identifies a set,
/// not a device. The agent knows, because the answer lives in its state
/// directory alongside the op-log.
fn this_device() -> Option<String> {
    let client = Client::with_default_path().ok().filter(Client::is_running)?;
    let device = client.sync_status().ok()?.device;
    (!device.is_empty()).then(|| passlib::sync::fingerprint_of(&device).to_string())
}

fn devices(vault_path: &Path) -> Result<()> {
    let (vault, _) = AgentOrPrompt::new(vault_path).open()?;
    let devices = vault.sync_devices();
    let me = this_device();

    if devices.is_empty() {
        println!("{}", "No devices registered yet.".yellow());
        println!("   Start an agent with {} on each device,", "pass agent run --sync".cyan());
        println!("   then pair them with {}.", "pass sync trust".cyan());
        return Ok(());
    }

    println!("{}", "🖥  Devices allowed to write into this vault".bold());
    println!();
    for device in devices {
        let tag = if me.as_deref() == Some(device.fingerprint.as_str()) {
            " (this device)".green()
        } else if vault.sync_device_identity(&device.fingerprint)?.is_some() {
            // Its signing key is in this file — because this vault was
            // copied from it, or it from this one.
            " (signing key present in this vault)".dimmed()
        } else {
            "".normal()
        };
        println!("   {} {}{}", device.label.bold(), device.fingerprint.dimmed(), tag);
        println!("     {}", device.public_key_string().dimmed());
    }
    Ok(())
}

fn id(vault_path: &Path) -> Result<()> {
    // The identity is created by the agent on unlock, because that is where
    // the epoch and the op-log live; there is nothing useful to print before
    // then, and creating one here would make a second one.
    let Some(fingerprint) = this_device() else {
        println!("{}", "This device has no sync identity yet.".yellow());
        println!("   Start the agent with {} and unlock the vault;", "pass agent run --sync".cyan());
        println!("   the identity is created then.");
        return Ok(());
    };

    let (vault, _) = AgentOrPrompt::new(vault_path).open()?;
    let device = vault
        .sync_devices()
        .into_iter()
        .find(|d| d.fingerprint == fingerprint)
        .with_context(|| format!("The agent is running as device {fingerprint}, which is not in this vault"))?;

    println!("{}", device.public_key_string());
    println!();
    println!("   {} {}", "Fingerprint:".dimmed(), device.fingerprint);
    println!("   Give this to your other device with:");
    println!("     {}", format!("pass sync trust {} <the key above>", device.label).cyan());
    Ok(())
}

fn trust(vault_path: &Path, label: &str, public_key: &str) -> Result<()> {
    let key = crypto::parse_public_key(public_key)
        .context("That is not a device key — run `pass sync id` on the other device")?;

    let access = AgentOrPrompt::new(vault_path);
    let (mut vault, password) = access.open()?;
    let fingerprint = vault.trust_sync_device(label, key)?;
    vault.save(&password).context("Failed to save vault")?;

    println!("{} {} ({})", "✓ Now trusting".green(), label.bold(), fingerprint.dimmed());
    println!();
    println!("   Trust is one-way: do the same on {label} with this device's key,");
    println!("   from {}.", "pass sync id".cyan());
    println!("   A running agent picks this up at its next round.");
    Ok(())
}

fn forget(vault_path: &Path, device: &str) -> Result<()> {
    let access = AgentOrPrompt::new(vault_path);
    let (mut vault, password) = access.open()?;

    // Accept either the fingerprint or the label, because the label is what
    // the user reads in `pass sync devices` and the fingerprint is what the
    // roster is keyed by.
    let fingerprint = vault
        .sync_devices()
        .into_iter()
        .find(|d| d.fingerprint == device || d.label.eq_ignore_ascii_case(device))
        .map(|d| d.fingerprint)
        .with_context(|| format!("No device called '{device}' — see `pass sync devices`"))?;

    if !vault.remove_sync_device(&fingerprint)? {
        anyhow::bail!("No device called '{device}'");
    }
    vault.save(&password).context("Failed to save vault")?;

    println!("{} {}", "✓ Forgotten:".green(), device.bold());
    println!();
    println!("   {}", "It can no longer write into this vault.".dimmed());
    println!(
        "   {}",
        "It has not forgotten anything it already read: if the device is lost, change the passwords."
            .yellow()
    );
    Ok(())
}
