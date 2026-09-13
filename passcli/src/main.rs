use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input, Password};
use passlib::{PasswordEntry, SyncHandle, Vault};
use std::path::{Path, PathBuf};

/// A secure, cross-platform password manager
#[derive(Parser)]
#[command(name = "pass")]
#[command(author = "Antonio Picone")]
#[command(version)]
#[command(about = "A secure password manager with zero-knowledge encryption", long_about = None)]
struct Cli {
    /// Path to the vault file. Defaults to the last vault successfully
    /// unlocked/created, or ~/.vaults/personal.kdbx if there isn't one yet
    /// — see `passlib::propose_vault_path`.
    #[arg(short, long)]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init {
        /// If pass-syncd finds an existing vault already synced on this
        /// network (same tailnet/LAN), import its entries immediately
        /// instead of starting empty — skips the interactive prompt.
        #[arg(long)]
        import_from_sync: bool,
    },

    /// Add a new password entry
    Add,
    
    /// List all password entries (without showing passwords)
    List,
    
    /// Get a specific password entry (shows password)
    Get {
        /// Entry ID or search term
        query: String,
    },
    
    /// Delete a password entry
    Delete {
        /// Entry ID to delete
        id: String,
    },
    
    /// Update an existing password entry
    Update {
        /// Entry ID to update
        id: String,
    },

    /// One-off import: merge entries from an unrelated KDBX file into this
    /// vault (e.g. a database you got from someone else, or an old backup).
    /// For keeping copies of *this same* vault in sync across your own
    /// devices, use `pass-syncd` instead — see `pass sync status` and the
    /// top-level README's "Cross-device sync" section.
    Merge {
        /// Path to the other KDBX file to merge from
        other: PathBuf,
    },

    /// Manage TOTP/MFA codes for an entry
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },

    /// Show this vault's real-time sync status (pass-syncd)
    Sync,

    /// Interactive mode - menu-driven interface for managing passwords
    Interactive,
}

#[derive(Subcommand)]
enum TotpAction {
    /// Attach an MFA secret to an entry, either by scanning a QR code image
    /// exported from the service's 2FA setup page or from an otpauth:// URI
    Add {
        /// Entry ID to attach the MFA secret to
        id: String,

        /// Path to a QR code image (PNG/JPEG/GIF/BMP/WebP)
        #[arg(long, conflicts_with = "uri")]
        qr: Option<PathBuf>,

        /// otpauth://totp/... URI, as an alternative to --qr
        #[arg(long, conflicts_with = "qr")]
        uri: Option<String>,
    },

    /// Show the current MFA code for an entry
    Show {
        /// Entry ID or search term
        query: String,
    },

    /// Remove the MFA secret from an entry
    Remove {
        /// Entry ID to remove the MFA secret from
        id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);
    let vault_path = cli.vault.unwrap_or_else(passlib::propose_vault_path);
    match cli.command {
        Commands::Init { import_from_sync } => cmd_init(&vault_path, import_from_sync),
        Commands::Add => cmd_add(&vault_path),
        Commands::List => cmd_list(&vault_path),
        Commands::Get { query } => cmd_get(&vault_path, &query),
        Commands::Delete { id } => cmd_delete(&vault_path, &id),
        Commands::Update { id } => cmd_update(&vault_path, &id),
        Commands::Merge { other } => cmd_merge(&vault_path, &other),
        Commands::Totp { action } => cmd_totp(&vault_path, action),
        Commands::Sync => cmd_sync_status(&vault_path),
        Commands::Interactive => cmd_interactive(&vault_path),
    }
}

/// Initialize a new vault. If `pass-syncd` is running and already knows a
/// synced vault on this network — some other device set one up first — the
/// user can import its entries right away instead of starting empty; see
/// [`passlib::sync::import_from_sync`].
fn cmd_init(vault_path: &PathBuf, import_from_sync: bool) -> Result<()> {
    println!("{}", "🔐 Initialize New Password Vault".bold().cyan());
    println!();

    if vault_path.exists() {
        anyhow::bail!("Vault file already exists at: {}", vault_path.display());
    }

    println!("{}", "⚠️  Important:".yellow().bold());
    println!("  • Your master password is the ONLY way to access your vault");
    println!("  • If you forget it, your passwords CANNOT be recovered");
    println!("  • Choose a strong, memorable passphrase");
    println!();

    let master_password = Password::new()
        .with_prompt("Enter master password")
        .with_confirmation("Confirm master password", "Passwords don't match")
        .interact()
        .context("Failed to read master password")?;

    if master_password.len() < 8 {
        anyhow::bail!("Master password must be at least 8 characters long");
    }

    let mut vault = Vault::init(vault_path, &master_password)
        .context("Failed to initialize vault")?;
    passlib::remember_last_vault(vault_path);

    println!();
    println!("{}", "✅ Vault created successfully!".green().bold());
    println!("   Location: {}", vault_path.display());

    // `discover_existing_salt` returns None both when pass-syncd isn't
    // reachable and when it's reachable but genuinely has nothing yet —
    // either way there's nothing to offer importing, so the prompt only
    // shows up when it's actually useful.
    let found_existing_sync = passlib::sync::discover_existing_salt().is_some();
    let should_import = import_from_sync
        || (found_existing_sync
            && Confirm::new()
                .with_prompt("pass-syncd found an existing vault already synced on this network — import its entries now?")
                .default(true)
                .interact()
                .unwrap_or(false));

    if should_import {
        match passlib::sync::import_from_sync(&mut vault, &master_password) {
            Some(n) => {
                vault.save(&master_password).context("Failed to save imported entries")?;
                println!(
                    "{}",
                    format!("🔄 Imported {n} entr{} from the synced vault.", if n == 1 { "y" } else { "ies" }).green()
                );
            }
            None => println!("{}", "No existing synced vault found on this network.".yellow()),
        }
    }

    println!();

    Ok(())
}

/// Add a new password entry
fn cmd_add(vault_path: &PathBuf) -> Result<()> {
    println!("{}", "➕ Add New Password Entry".bold().cyan());
    println!();

    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;

    println!();
    let website = Input::<String>::new()
        .with_prompt("Website name")
        .interact_text()
        .context("Failed to read website name")?;

    let url = Input::<String>::new()
        .with_prompt("URL")
        .with_initial_text("https://")
        .interact_text()
        .context("Failed to read URL")?;

    let username = Input::<String>::new()
        .with_prompt("Username/Email")
        .interact_text()
        .context("Failed to read username")?;

    let password = Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;

    let entry = PasswordEntry::new(website.clone(), url, username, password);
    let id = vault.add_entry(entry)
        .context("Failed to add entry")?;

    let salt = vault.ensure_sync_salt();
    vault.save(&master_password)
        .context("Failed to save vault")?;
    sync_push_upsert(&vault, &master_password, salt, &id);

    println!();
    println!("{}", "✅ Password entry added successfully!".green().bold());
    println!("   Website: {}", website);
    println!("   ID: {}", id.bright_black());
    println!();

    Ok(())
}

/// List all password entries
fn cmd_list(vault_path: &PathBuf) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    let entries = vault.list_entries()
        .context("Failed to list entries")?;

    println!();
    if entries.is_empty() {
        println!("{}", "No password entries found.".yellow());
        println!("Use {} to add a new entry.", "pass add".cyan());
    } else {
        println!("{}", format!("📋 Password Entries ({} total)", entries.len()).bold().cyan());
        println!();
        
        for entry in entries {
            println!("{}", "─".repeat(60).bright_black());
            println!("{}: {}", "Website".bold(), entry.website);
            println!("{}: {}", "URL".bold(), entry.url);
            println!("{}: {}", "Username".bold(), entry.username);
            println!("{}: {}", "ID".bright_black(), entry.id.bright_black());
            println!("{}: {}", "Created".bright_black(), 
                     entry.created_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
            println!();
        }
        println!("{}", "─".repeat(60).bright_black());
        println!();
        println!("💡 Use {} to view a password", "pass get <id>".cyan());
    }
    println!();

    Ok(())
}

/// Find an entry by ID, falling back to a case-insensitive website search
fn find_entry(vault: &Vault, query: &str) -> Result<PasswordEntry> {
    vault
        .get_entry(query)
        .or_else(|_| {
            let entries = vault.list_entries()?;
            let found = entries
                .iter()
                .find(|e| e.website.to_lowercase().contains(&query.to_lowercase()))
                .ok_or_else(|| passlib::PassError::EntryNotFound(query.to_string()))?;
            vault.get_entry(&found.id)
        })
        .context(format!("Entry not found: {}", query))
}

/// Print the current TOTP code and remaining seconds for an entry, if any
fn print_totp_line(entry: &PasswordEntry) {
    if let Some(totp) = &entry.totp {
        let now = chrono::Utc::now();
        match passlib::totp::generate_code(totp, now) {
            Ok(code) => {
                let remaining = passlib::totp::seconds_remaining(totp, now);
                println!(
                    "{}: {} {}",
                    "MFA code".bold(),
                    code.green().bold(),
                    format!("(expires in {}s)", remaining).bright_black()
                );
            }
            Err(e) => println!("{}: {}", "MFA code".bold(), format!("error: {}", e).red()),
        }
    }
}

/// Get a specific password entry
fn cmd_get(vault_path: &PathBuf, query: &str) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    let entry = find_entry(&vault, query)?;

    println!();
    println!("{}", "🔑 Password Entry".bold().cyan());
    println!();
    println!("{}", "─".repeat(60).bright_black());
    println!("{}: {}", "Website".bold(), entry.website);
    println!("{}: {}", "URL".bold(), entry.url);
    println!("{}: {}", "Username".bold(), entry.username);
    println!("{}: {}", "Password".bold().green(), entry.password().green());
    print_totp_line(&entry);
    println!("{}: {}", "ID".bright_black(), entry.id.bright_black());
    println!("{}: {}", "Created".bright_black(),
             entry.created_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!("{}: {}", "Updated".bright_black(),
             entry.updated_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!("{}", "─".repeat(60).bright_black());
    println!();

    Ok(())
}

/// Delete a password entry
fn cmd_delete(vault_path: &PathBuf, id: &str) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    // Show the entry before deleting
    let entry = vault.get_entry(id)
        .context(format!("Entry not found: {}", id))?;

    println!();
    println!("About to delete:");
    println!("  Website: {}", entry.website);
    println!("  Username: {}", entry.username);
    println!();

    let confirmed = Confirm::new()
        .with_prompt("Are you sure you want to delete this entry?")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?;

    if !confirmed {
        println!("{}", "Deletion cancelled.".yellow());
        return Ok(());
    }

    vault.delete_entry(id)
        .context("Failed to delete entry")?;

    let salt = vault.ensure_sync_salt();
    vault.save(&master_password)
        .context("Failed to save vault")?;
    sync_push_delete(&vault, &master_password, salt, id);

    println!();
    println!("{}", "✅ Password entry deleted successfully!".green().bold());
    println!();

    Ok(())
}

/// Update a password entry
fn cmd_update(vault_path: &PathBuf, id: &str) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    // Show current values
    let entry = vault.get_entry(id)
        .context(format!("Entry not found: {}", id))?;

    println!();
    println!("{}", "📝 Update Password Entry".bold().cyan());
    println!("(Leave blank to keep current value)");
    println!();

    let website = Input::<String>::new()
        .with_prompt("Website name")
        .default(entry.website.clone())
        .allow_empty(true)
        .interact_text()
        .context("Failed to read website name")?;

    let url = Input::<String>::new()
        .with_prompt("URL")
        .default(entry.url.clone())
        .allow_empty(true)
        .interact_text()
        .context("Failed to read URL")?;

    let username = Input::<String>::new()
        .with_prompt("Username/Email")
        .default(entry.username.clone())
        .allow_empty(true)
        .interact_text()
        .context("Failed to read username")?;

    let update_password = Confirm::new()
        .with_prompt("Update password?")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?;

    let password = if update_password {
        Some(Password::new()
            .with_prompt("New password")
            .interact()
            .context("Failed to read password")?)
    } else {
        None
    };

    vault.update_entry(
        id,
        Some(website),
        Some(url),
        Some(username),
        password,
        None,
        None,
    ).context("Failed to update entry")?;

    let salt = vault.ensure_sync_salt();
    vault.save(&master_password)
        .context("Failed to save vault")?;
    sync_push_upsert(&vault, &master_password, salt, id);

    println!();
    println!("{}", "✅ Password entry updated successfully!".green().bold());
    println!();

    Ok(())
}

/// Merge another copy of the vault (e.g. a copy synced via Nextcloud) into this one
fn cmd_merge(vault_path: &PathBuf, other_path: &PathBuf) -> Result<()> {
    println!("{}", "🔀 Merge Vault".bold().cyan());
    println!();

    if !other_path.exists() {
        anyhow::bail!("Other vault file not found: {}", other_path.display());
    }

    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;

    let summary = vault
        .merge_from_file(other_path, &master_password)
        .context("Failed to merge vault (wrong password on the other vault?)")?;

    vault.save(&master_password)
        .context("Failed to save merged vault")?;

    println!();
    println!("{}", "✅ Merge complete!".green().bold());
    println!("   Created:   {}", summary.created);
    println!("   Updated:   {}", summary.updated);
    println!("   Unchanged: {}", summary.unchanged);
    if summary.deleted > 0 {
        println!(
            "   {}",
            format!("Deleted (or moved to Recycle Bin): {}", summary.deleted).yellow()
        );
    }
    println!();

    Ok(())
}

/// Manage the TOTP/MFA secret attached to an entry
fn cmd_totp(vault_path: &PathBuf, action: TotpAction) -> Result<()> {
    match action {
        TotpAction::Add { id, qr, uri } => cmd_totp_add(vault_path, &id, &qr, &uri),
        TotpAction::Show { query } => cmd_totp_show(vault_path, &query),
        TotpAction::Remove { id } => cmd_totp_remove(vault_path, &id),
    }
}

/// Decode the first QR code found in an image file into its raw text content
fn decode_qr_image(path: &Path) -> Result<String> {
    let img = image::open(path)
        .with_context(|| format!("Failed to open image: {}", path.display()))?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    let grid = grids
        .first()
        .ok_or_else(|| anyhow::anyhow!("No QR code found in {}", path.display()))?;

    let (_meta, content) = grid
        .decode()
        .with_context(|| format!("Failed to decode QR code in {}", path.display()))?;

    Ok(content)
}

/// Attach an MFA secret to an entry, from a QR code image or a raw otpauth URI
fn cmd_totp_add(vault_path: &PathBuf, id: &str, qr: &Option<PathBuf>, uri: &Option<String>) -> Result<()> {
    println!("{}", "📷 Add MFA Code".bold().cyan());
    println!();

    let otpauth_uri = match (qr, uri) {
        (Some(path), None) => {
            println!("Reading QR code from {}…", path.display());
            decode_qr_image(path)?
        }
        (None, Some(uri)) => uri.clone(),
        _ => anyhow::bail!("Provide exactly one of --qr <image> or --uri <otpauth-uri>"),
    };

    let totp = passlib::totp::parse_otpauth_uri(&otpauth_uri)
        .context("Failed to parse the otpauth URI (is this a TOTP QR code?)")?;

    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    let website = vault
        .get_entry(id)
        .context(format!("Entry not found: {}", id))?
        .website
        .clone();

    vault.set_entry_totp(id, totp.clone())
        .context("Failed to attach MFA secret")?;
    let salt = vault.ensure_sync_salt();
    vault.save(&master_password)
        .context("Failed to save vault")?;
    sync_push_upsert(&vault, &master_password, salt, id);

    println!();
    println!("{}", format!("✅ MFA code added to '{}'.", website).green().bold());
    if let Some(issuer) = &totp.issuer {
        println!("   Issuer: {}", issuer);
    }
    println!("   {} digits, every {}s, {:?}", totp.digits, totp.period, totp.algorithm);
    println!();

    Ok(())
}

/// Show the current MFA code for an entry
fn cmd_totp_show(vault_path: &PathBuf, query: &str) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    let entry = find_entry(&vault, query)?;
    let totp = entry
        .totp
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("'{}' has no MFA code configured. Add one with: pass totp add", entry.website))?;

    let now = chrono::Utc::now();
    let code = passlib::totp::generate_code(totp, now).context("Failed to generate MFA code")?;
    let remaining = passlib::totp::seconds_remaining(totp, now);

    println!();
    println!("{}", "🔢 MFA Code".bold().cyan());
    println!("{}", "─".repeat(40).bright_black());
    println!("{}: {}", "Website".bold(), entry.website);
    println!("{}: {}", "Code".bold().green(), code.green().bold());
    println!("{}: {}s", "Expires in".bright_black(), remaining);
    println!("{}", "─".repeat(40).bright_black());
    println!();

    Ok(())
}

/// Remove the MFA secret from an entry
fn cmd_totp_remove(vault_path: &PathBuf, id: &str) -> Result<()> {
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    let website = vault
        .get_entry(id)
        .context(format!("Entry not found: {}", id))?
        .website
        .clone();

    vault.clear_entry_totp(id)
        .context("Failed to remove MFA secret")?;
    let salt = vault.ensure_sync_salt();
    vault.save(&master_password)
        .context("Failed to save vault")?;
    sync_push_upsert(&vault, &master_password, salt, id);

    println!();
    println!("{}", format!("✅ MFA code removed from '{}'.", website).green().bold());
    println!();

    Ok(())
}

/// Show this vault's real-time sync status: whether `pass-syncd` is
/// reachable and, if so, how many entries it currently holds for this
/// vault. See `pass-syncd/README.md` for installing/pairing the daemon —
/// every add/update/delete already pushes to it automatically when it's
/// running, so there's nothing else to configure here.
fn cmd_sync_status(vault_path: &PathBuf) -> Result<()> {
    println!("{}", "🔄 Sync Status".bold().cyan());
    println!();

    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;

    match vault.sync_salt() {
        None => {
            println!("{}", "Sync has not been set up for this vault yet.".yellow());
            println!("It will be automatically the next time you add, update, or delete an entry.");
        }
        Some(_) => match SyncHandle::for_vault(&vault, &master_password) {
            Some(handle) => {
                let changed = handle.pull_and_apply(&mut vault);
                if changed > 0 {
                    vault.save(&master_password).context("Failed to save synced changes")?;
                }
                println!("{}: {}", "pass-syncd".bold(), "reachable".green());
                println!("{}: {}", "Entries after sync".bold(), vault.len());
                if changed > 0 {
                    println!("{}: {}", "Just synced".bold(), format!("{changed} change(s) from another device").green());
                }
            }
            None => println!("{}: {}", "pass-syncd".bold(), "unreachable (not installed or not running?)".red()),
        },
    }
    println!();

    Ok(())
}

/// Pulls and applies any changes `pass-syncd` has for this vault, saving if
/// anything actually changed. Best-effort and silent when there's nothing
/// new or the daemon isn't reachable — see [`SyncHandle`]'s own doc
/// comment for the full non-fatal-by-design contract.
fn sync_pull(vault: &mut Vault, master_password: &str) -> Result<()> {
    let Some(handle) = SyncHandle::for_vault(vault, master_password) else {
        return Ok(());
    };
    let changed = handle.pull_and_apply(vault);
    if changed > 0 {
        vault.save(master_password).context("Failed to save synced changes")?;
        println!("{}", format!("🔄 Synced {changed} change(s) from another device.").bright_black());
    }
    Ok(())
}

/// Pushes entry `id`'s current state to `pass-syncd`. `salt` must come from
/// [`Vault::ensure_sync_salt`] called *before* the local mutation was
/// saved (so a freshly generated salt is already on disk by the time this
/// runs, not stranded in memory for one process only) — every call site
/// below follows that order. Best-effort — see [`SyncHandle::push_upsert`].
fn sync_push_upsert(vault: &Vault, master_password: &str, salt: [u8; 16], id: &str) {
    if let Ok(entry) = vault.get_entry(id) {
        SyncHandle::new(vault.path(), salt, master_password).push_upsert(&entry);
    }
}

/// Pushes entry `id`'s deletion to `pass-syncd`. See [`sync_push_upsert`]
/// for the salt-ordering contract.
fn sync_push_delete(vault: &Vault, master_password: &str, salt: [u8; 16], id: &str) {
    SyncHandle::new(vault.path(), salt, master_password).push_delete(id);
}

/// Prompt for master password securely
fn prompt_master_password() -> Result<String> {
    Password::new()
        .with_prompt("Master password")
        .interact()
        .context("Failed to read master password")
}

/// Unlocks `vault_path` interactively: offers "unlock with your face" via
/// howdy first when it's been enabled for this vault (see `pass-howdy`),
/// falling back to the master password prompt otherwise or if the face
/// scan doesn't produce a working password. Right after a successful
/// *manual* unlock, also offers to enable face unlock for next time if
/// howdy is available but this vault hasn't opted in yet. This is the
/// interactive-unlock counterpart to a bare `prompt_master_password()` +
/// `Vault::unlock` pair, used by every command that needs an unlocked
/// vault.
fn unlock_vault_interactive(vault_path: &Path) -> Result<(Vault, String)> {
    if pass_howdy::is_available_for(vault_path) {
        let use_face = Confirm::new()
            .with_prompt("Unlock with your face?")
            .default(true)
            .interact()
            .unwrap_or(false);
        if use_face {
            match pass_howdy::unlock_with_face(vault_path)
                .map_err(|e| e.to_string())
                .and_then(|pw| Vault::unlock(vault_path, &pw).map(|v| (v, pw)).map_err(|e| e.to_string()))
            {
                Ok((vault, password)) => {
                    passlib::remember_last_vault(vault_path);
                    return Ok((vault, password));
                }
                Err(e) => println!("{}", format!("Face unlock failed ({e}); falling back to your master password.").yellow()),
            }
        }
    }

    let master_password = prompt_master_password()?;
    let vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;
    passlib::remember_last_vault(vault_path);

    offer_howdy_enrollment(vault_path, &master_password);

    Ok((vault, master_password))
}

/// Right after a successful manual unlock: if howdy is installed and its
/// PAM service is configured but this vault hasn't opted in to face
/// unlock yet, offers to enable it (see `pass-howdy::store_password`).
/// Best-effort/silent about failures — this is a nice-to-have, never
/// something that should turn a successful unlock into an error.
fn offer_howdy_enrollment(vault_path: &Path, master_password: &str) {
    if !pass_howdy::can_enroll() || pass_howdy::has_stored_password(vault_path) {
        return;
    }
    let enable = Confirm::new()
        .with_prompt("Enable \"unlock with your face\" (howdy) for this vault?")
        .default(false)
        .interact()
        .unwrap_or(false);
    if enable {
        match pass_howdy::store_password(vault_path, master_password) {
            Ok(()) => println!("{}", "✅ Face unlock enabled for this vault.".green()),
            Err(e) => println!("{}", format!("Could not enable face unlock: {e}").red()),
        }
    }
}

#[cfg(test)]
mod totp_tests {
    use super::*;

    /// testdata/totp_qr.png encodes this exact otpauth URI (generated with
    /// Python's `qrcode` library) — a real QR image end to end, not just
    /// the URI parser.
    #[test]
    fn decode_qr_image_reads_the_encoded_otpauth_uri() {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/totp_qr.png"));
        let content = decode_qr_image(path).unwrap();

        assert_eq!(
            content,
            "otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
        );

        let totp = passlib::totp::parse_otpauth_uri(&content).unwrap();
        assert_eq!(totp.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(totp.issuer.as_deref(), Some("GitHub"));
        assert_eq!(totp.account.as_deref(), Some("me@example.com"));
    }
}

/// Interactive mode - menu-driven interface
fn cmd_interactive(vault_path: &PathBuf) -> Result<()> {
    // Check if vault exists
    if !vault_path.exists() {
        println!("{}", "❌ Vault not found!".red().bold());
        println!();
        println!("Please initialize a vault first with: {}", "pass init".cyan());
        println!();
        return Ok(());
    }

    // Unlock vault once for the session
    println!("{}", "🔐 Password Manager - Interactive Mode".bold().cyan());
    println!();
    
    let (mut vault, master_password) = unlock_vault_interactive(vault_path)?;
    sync_pull(&mut vault, &master_password)?;

    // Display header
    print_header(&vault, vault_path);

    // Main loop
    loop {
        // Best-effort refresh from other devices before every menu render —
        // cheap (a no-op fast path once nothing changed, see
        // SyncHandle::pull_and_apply's fingerprint check) and keeps a
        // long-lived interactive session from going stale.
        sync_pull(&mut vault, &master_password)?;

        match show_main_menu()? {
            MainMenuAction::ListAll => {
                if let Err(e) = interactive_list(&vault) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::Search => {
                if let Err(e) = interactive_search(&vault) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::Add => {
                if let Err(e) = interactive_add(&mut vault, &master_password) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::Edit => {
                if let Err(e) = interactive_edit(&mut vault, &master_password) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::Delete => {
                if let Err(e) = interactive_delete(&mut vault, &master_password) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::ViewPassword => {
                if let Err(e) = interactive_view(&vault) {
                    println!("{}", format!("Error: {}", e).red());
                }
            }
            MainMenuAction::Exit => {
                println!();
                println!("{}", "👋 Goodbye! Vault locked.".cyan());
                println!();
                break;
            }
        }
        
        println!();
    }

    Ok(())
}

#[derive(Debug)]
enum MainMenuAction {
    ListAll,
    Search,
    Add,
    Edit,
    Delete,
    ViewPassword,
    Exit,
}

fn print_header(vault: &Vault, vault_path: &PathBuf) {
    println!();
    println!("{}", "╔════════════════════════════════════════╗".bright_black());
    println!("{}", "║   Password Manager - Interactive Mode  ║".bright_black());
    println!("{}", "╚════════════════════════════════════════╝".bright_black());
    println!();
    println!("  {}: {}", "Vault".bright_black(), vault_path.display());
    println!("  {}: {} {}", "Status".bright_black(), "Unlocked".green(), format!("({} entries)", vault.len()).bright_black());
    println!();
}

fn show_main_menu() -> Result<MainMenuAction> {
    println!("{}", "─".repeat(60).bright_black());
    println!();
    println!("{}", "What would you like to do?".bold());
    println!();
    
    let options = vec![
        "📋 List all passwords",
        "🔍 Search passwords",
        "➕ Add new password",
        "✏️  Edit password",
        "🗑️  Delete password",
        "🔑 View specific password",
        "🚪 Exit",
    ];
    
    let selection = dialoguer::Select::new()
        .items(&options)
        .default(0)
        .interact()
        .context("Failed to read selection")?;

    Ok(match selection {
        0 => MainMenuAction::ListAll,
        1 => MainMenuAction::Search,
        2 => MainMenuAction::Add,
        3 => MainMenuAction::Edit,
        4 => MainMenuAction::Delete,
        5 => MainMenuAction::ViewPassword,
        6 => MainMenuAction::Exit,
        _ => MainMenuAction::Exit,
    })
}

fn interactive_list(vault: &Vault) -> Result<()> {
    println!();
    println!("{}", "╔════════════════════════════════════════╗".bright_black());
    println!("{}", format!("║   Your Passwords ({:2} entries)         ║", vault.len()).bright_black());
    println!("{}", "╚════════════════════════════════════════╝".bright_black());
    println!();

    let entries = vault.list_entries()?;
    
    if entries.is_empty() {
        println!("{}", "  No passwords stored yet.".yellow());
        println!("  Use {} to add your first password.", "Add new password".cyan());
        return Ok(());
    }

    for (i, entry) in entries.iter().enumerate() {
        println!("  {}. {}", (i + 1).to_string().cyan().bold(), entry.website.bold());
        println!("     {} {} | {}", 
                 "└─".bright_black(),
                 entry.username,
                 entry.url.bright_black());
        println!();
    }

    Ok(())
}

fn interactive_search(vault: &Vault) -> Result<()> {
    println!();
    let query = Input::<String>::new()
        .with_prompt("Search for")
        .interact_text()
        .context("Failed to read search query")?;

    let entries = vault.list_entries()?;
    let matches: Vec<_> = entries.iter()
        .filter(|e| {
            e.website.to_lowercase().contains(&query.to_lowercase()) ||
            e.username.to_lowercase().contains(&query.to_lowercase()) ||
            e.url.to_lowercase().contains(&query.to_lowercase())
        })
        .collect();

    println!();
    if matches.is_empty() {
        println!("{}", format!("No matches found for '{}'", query).yellow());
    } else {
        println!("{}", format!("Found {} match(es):", matches.len()).green().bold());
        println!();
        for (i, entry) in matches.iter().enumerate() {
            println!("  {}. {}", (i + 1).to_string().cyan().bold(), entry.website.bold());
            println!("     {} {} | {}", 
                     "└─".bright_black(),
                     entry.username,
                     entry.url.bright_black());
            println!();
        }
    }

    Ok(())
}

fn interactive_add(vault: &mut Vault, master_password: &str) -> Result<()> {
    println!();
    println!("{}", "╔════════════════════════════════════════╗".bright_black());
    println!("{}", "║   Add New Password                     ║".bright_black());
    println!("{}", "╚════════════════════════════════════════╝".bright_black());
    println!();

    let website = Input::<String>::new()
        .with_prompt("Website name")
        .interact_text()
        .context("Failed to read website name")?;

    let url = Input::<String>::new()
        .with_prompt("URL")
        .with_initial_text("https://")
        .interact_text()
        .context("Failed to read URL")?;

    let username = Input::<String>::new()
        .with_prompt("Username/Email")
        .interact_text()
        .context("Failed to read username")?;

    let password = Password::new()
        .with_prompt("Password")
        .interact()
        .context("Failed to read password")?;

    let entry = PasswordEntry::new(website.clone(), url, username, password);
    let id = vault.add_entry(entry)?;
    let salt = vault.ensure_sync_salt();
    vault.save(master_password)?;
    sync_push_upsert(vault, master_password, salt, &id);

    println!();
    println!("{}", format!("✅ '{}' added successfully!", website).green().bold());

    Ok(())
}

fn interactive_edit(vault: &mut Vault, master_password: &str) -> Result<()> {
    let entries = vault.list_entries()?;
    
    if entries.is_empty() {
        println!();
        println!("{}", "No passwords to edit.".yellow());
        return Ok(());
    }

    println!();
    let items: Vec<String> = entries.iter()
        .map(|e| format!("{} ({})", e.website, e.username))
        .collect();

    let selection = dialoguer::Select::new()
        .with_prompt("Select password to edit")
        .items(&items)
        .interact()
        .context("Failed to read selection")?;

    let entry_id = entries[selection].id.clone();
    let entry = vault.get_entry(&entry_id)?;

    println!();
    println!("{}", format!("Editing: {}", entry.website).cyan().bold());
    println!("(Press Enter to keep current value)");
    println!();

    let website = Input::<String>::new()
        .with_prompt("Website name")
        .default(entry.website.clone())
        .show_default(true)
        .interact_text()
        .context("Failed to read website name")?;

    let url = Input::<String>::new()
        .with_prompt("URL")
        .default(entry.url.clone())
        .show_default(true)
        .interact_text()
        .context("Failed to read URL")?;

    let username = Input::<String>::new()
        .with_prompt("Username/Email")
        .default(entry.username.clone())
        .show_default(true)
        .interact_text()
        .context("Failed to read username")?;

    let update_password = Confirm::new()
        .with_prompt("Update password?")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?;

    let password = if update_password {
        Some(Password::new()
            .with_prompt("New password")
            .interact()
            .context("Failed to read password")?)
    } else {
        None
    };

    vault.update_entry(&entry_id, Some(website), Some(url), Some(username), password, None, None)?;
    let salt = vault.ensure_sync_salt();
    vault.save(master_password)?;
    sync_push_upsert(vault, master_password, salt, &entry_id);

    println!();
    println!("{}", "✅ Password updated successfully!".green().bold());

    Ok(())
}

fn interactive_delete(vault: &mut Vault, master_password: &str) -> Result<()> {
    let entries = vault.list_entries()?;
    
    if entries.is_empty() {
        println!();
        println!("{}", "No passwords to delete.".yellow());
        return Ok(());
    }

    println!();
    let items: Vec<String> = entries.iter()
        .map(|e| format!("{} ({})", e.website, e.username))
        .collect();

    let selection = dialoguer::Select::new()
        .with_prompt("Select password to delete")
        .items(&items)
        .interact()
        .context("Failed to read selection")?;

    let entry_id = entries[selection].id.clone();
    let entry = vault.get_entry(&entry_id)?;

    println!();
    println!("{}", "About to delete:".yellow().bold());
    println!("  Website: {}", entry.website);
    println!("  Username: {}", entry.username);
    println!();

    let confirmed = Confirm::new()
        .with_prompt("Are you sure?")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?;

    if !confirmed {
        println!("{}", "Deletion cancelled.".yellow());
        return Ok(());
    }

    vault.delete_entry(&entry_id)?;
    let salt = vault.ensure_sync_salt();
    vault.save(master_password)?;
    sync_push_delete(vault, master_password, salt, &entry_id);

    println!();
    println!("{}", "✅ Password deleted successfully!".green().bold());

    Ok(())
}

fn interactive_view(vault: &Vault) -> Result<()> {
    let entries = vault.list_entries()?;
    
    if entries.is_empty() {
        println!();
        println!("{}", "No passwords to view.".yellow());
        return Ok(());
    }

    println!();
    let items: Vec<String> = entries.iter()
        .map(|e| format!("{} ({})", e.website, e.username))
        .collect();

    let selection = dialoguer::Select::new()
        .with_prompt("Select password to view")
        .items(&items)
        .interact()
        .context("Failed to read selection")?;

    let entry_id = entries[selection].id.clone();
    let entry = vault.get_entry(&entry_id)?;

    println!();
    println!("{}", "╔════════════════════════════════════════╗".bright_black());
    println!("{}", format!("║   {}{}║", entry.website, " ".repeat(40 - entry.website.len())).bright_black());
    println!("{}", "╚════════════════════════════════════════╝".bright_black());
    println!();
    println!("{}: {}", "Website".bright_black(), entry.website.bold());
    println!("{}: {}", "URL".bright_black(), entry.url);
    println!("{}: {}", "Username".bright_black(), entry.username.cyan());
    println!("{}: {}", "Password".bright_black(), entry.password().green().bold());
    print_totp_line(&entry);
    println!();
    println!("{}: {}", "Created".bright_black(),
             entry.created_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!("{}: {}", "Updated".bright_black(), 
             entry.updated_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!();

    Ok(())
}
