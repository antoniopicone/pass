use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input, Password};
use notify::{Event, RecursiveMode, Watcher};
use passlib::{PasswordEntry, Vault};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

const DEFAULT_VAULT_PATH: &str = "passwords.kdbx";

/// A secure, cross-platform password manager
#[derive(Parser)]
#[command(name = "pass")]
#[command(author = "Antonio Picone")]
#[command(version)]
#[command(about = "A secure password manager with zero-knowledge encryption", long_about = None)]
struct Cli {
    /// Path to the vault file
    #[arg(short, long, default_value = DEFAULT_VAULT_PATH)]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new password vault
    Init,
    
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

    /// Merge another copy of this vault (e.g. synced via Nextcloud) into it
    Merge {
        /// Path to the other vault file to merge from
        other: PathBuf,
    },

    /// Manage TOTP/MFA codes for an entry
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },

    /// Watch another vault copy (e.g. synced via Nextcloud) and automatically
    /// merge changes into this vault as they appear
    Watch {
        /// Path to the other vault file to watch and merge from
        other: PathBuf,

        /// Also copy the merged vault to this path after each merge, e.g. to
        /// publish it back to a shared/synced location for other devices
        #[arg(long)]
        publish: Option<PathBuf>,

        /// Quiet period (ms) after a change is detected before merging, to
        /// coalesce the burst of filesystem events a single save produces
        #[arg(long, default_value_t = 500)]
        debounce_ms: u64,
    },

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

    match cli.command {
        Commands::Init => cmd_init(&cli.vault),
        Commands::Add => cmd_add(&cli.vault),
        Commands::List => cmd_list(&cli.vault),
        Commands::Get { query } => cmd_get(&cli.vault, &query),
        Commands::Delete { id } => cmd_delete(&cli.vault, &id),
        Commands::Update { id } => cmd_update(&cli.vault, &id),
        Commands::Merge { other } => cmd_merge(&cli.vault, &other),
        Commands::Totp { action } => cmd_totp(&cli.vault, action),
        Commands::Watch {
            other,
            publish,
            debounce_ms,
        } => cmd_watch(&cli.vault, &other, &publish, debounce_ms),
        Commands::Interactive => cmd_interactive(&cli.vault),
    }
}

/// Initialize a new vault
fn cmd_init(vault_path: &PathBuf) -> Result<()> {
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

    Vault::init(vault_path, &master_password)
        .context("Failed to initialize vault")?;

    println!();
    println!("{}", "✅ Vault created successfully!".green().bold());
    println!("   Location: {}", vault_path.display());
    println!();

    Ok(())
}

/// Add a new password entry
fn cmd_add(vault_path: &PathBuf) -> Result<()> {
    println!("{}", "➕ Add New Password Entry".bold().cyan());
    println!();

    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    
    vault.save(&master_password)
        .context("Failed to save vault")?;

    println!();
    println!("{}", "✅ Password entry added successfully!".green().bold());
    println!("   Website: {}", website);
    println!("   ID: {}", id.bright_black());
    println!();

    Ok(())
}

/// List all password entries
fn cmd_list(vault_path: &PathBuf) -> Result<()> {
    let master_password = prompt_master_password()?;
    let vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    let master_password = prompt_master_password()?;
    let vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    
    vault.save(&master_password)
        .context("Failed to save vault")?;

    println!();
    println!("{}", "✅ Password entry deleted successfully!".green().bold());
    println!();

    Ok(())
}

/// Update a password entry
fn cmd_update(vault_path: &PathBuf, id: &str) -> Result<()> {
    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    ).context("Failed to update entry")?;

    vault.save(&master_password)
        .context("Failed to save vault")?;

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

    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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

    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

    let website = vault
        .get_entry(id)
        .context(format!("Entry not found: {}", id))?
        .website
        .clone();

    vault.set_entry_totp(id, totp.clone())
        .context("Failed to attach MFA secret")?;
    vault.save(&master_password)
        .context("Failed to save vault")?;

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
    let master_password = prompt_master_password()?;
    let vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

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
    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

    let website = vault
        .get_entry(id)
        .context(format!("Entry not found: {}", id))?
        .website
        .clone();

    vault.clear_entry_totp(id)
        .context("Failed to remove MFA secret")?;
    vault.save(&master_password)
        .context("Failed to save vault")?;

    println!();
    println!("{}", format!("✅ MFA code removed from '{}'.", website).green().bold());
    println!();

    Ok(())
}

/// Watch another vault copy and automatically merge changes into this one
/// as they appear on disk (e.g. because a Nextcloud client just synced them
/// down from another device).
fn cmd_watch(
    vault_path: &PathBuf,
    other_path: &PathBuf,
    publish: &Option<PathBuf>,
    debounce_ms: u64,
) -> Result<()> {
    println!("{}", "👀 Watch & Auto-Merge".bold().cyan());
    println!();

    if !other_path.exists() {
        anyhow::bail!("Path to watch not found: {}", other_path.display());
    }

    let master_password = prompt_master_password()?;
    // Fail fast on a wrong password instead of only discovering it once a
    // change eventually comes in.
    Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

    println!();
    println!("Checking for changes already waiting in {}…", other_path.display());
    run_merge(vault_path, other_path, publish, &master_password)?;

    println!();
    println!(
        "Watching {} for changes. Press Ctrl+C to stop.",
        other_path.display()
    );
    println!();

    watch_and_merge(vault_path, other_path, publish, &master_password, debounce_ms, None)
}

/// Core watch loop: blocks on filesystem events for `other_path` and
/// re-merges whenever it changes. `max_iterations` bounds how many merges
/// to perform before returning (`None` runs until the watch channel closes,
/// which in practice means forever); it exists so this loop can be driven
/// deterministically from a test instead of running forever.
fn watch_and_merge(
    vault_path: &Path,
    other_path: &Path,
    publish: &Option<PathBuf>,
    master_password: &str,
    debounce_ms: u64,
    max_iterations: Option<usize>,
) -> Result<()> {
    let watch_dir = match other_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let target_name = other_path.file_name().map(|n| n.to_owned());

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })
    .context("Failed to start filesystem watcher")?;
    watcher
        .watch(watch_dir, RecursiveMode::NonRecursive)
        .context("Failed to watch directory")?;

    let mut merges_done = 0;
    loop {
        let first = match rx.recv() {
            Ok(event) => event,
            Err(_) => break, // watcher was dropped / channel closed
        };
        if !event_touches(&first, target_name.as_deref()) {
            continue;
        }

        // Drain further events for a short quiet period so a single atomic
        // save (which can fire create + modify + rename events) triggers
        // exactly one merge instead of several.
        while rx.recv_timeout(Duration::from_millis(debounce_ms)).is_ok() {}

        if let Err(e) = run_merge(vault_path, other_path, publish, master_password) {
            println!("{}", format!("⚠️  Merge failed: {}", e).red());
        }

        merges_done += 1;
        if max_iterations.is_some_and(|max| merges_done >= max) {
            break;
        }
    }

    Ok(())
}

/// Whether a filesystem event is plausibly about the watched file. Some
/// platforms report events without a path, in which case we merge anyway
/// (a no-op merge is harmless) rather than risk missing a real change.
fn event_touches(event: &Event, target_name: Option<&std::ffi::OsStr>) -> bool {
    event.paths.is_empty()
        || event
            .paths
            .iter()
            .any(|p| p.file_name() == target_name)
}

/// Merge `other_path` into the vault at `vault_path`, save if anything
/// changed, and optionally publish a copy of the result to `publish`.
fn run_merge(
    vault_path: &Path,
    other_path: &Path,
    publish: &Option<PathBuf>,
    master_password: &str,
) -> Result<()> {
    if !other_path.exists() {
        // Transient: a sync client can briefly remove/replace the file
        // mid-write. Nothing to merge yet; the next event will catch it.
        return Ok(());
    }

    let mut vault =
        Vault::unlock(vault_path, master_password).context("Failed to unlock local vault")?;

    let summary = vault
        .merge_from_file(other_path, master_password)
        .context("Failed to merge (wrong password on the watched vault?)")?;

    if !summary.changed() {
        println!("No changes in {}.", other_path.display());
        return Ok(());
    }

    vault.save(master_password).context("Failed to save merged vault")?;

    println!(
        "{}",
        format!(
            "🔄 Merged from {} — created {}, updated {}, {} deleted.",
            other_path.display(),
            summary.created,
            summary.updated,
            summary.deleted
        )
        .green()
    );

    if let Some(publish_path) = publish {
        std::fs::copy(vault_path, publish_path)
            .with_context(|| format!("Failed to publish merged vault to {}", publish_path.display()))?;
        println!("   Published to {}", publish_path.display());
    }

    Ok(())
}

/// Prompt for master password securely
fn prompt_master_password() -> Result<String> {
    Password::new()
        .with_prompt("Master password")
        .interact()
        .context("Failed to read master password")
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

#[cfg(test)]
mod watch_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn event_touches_matches_only_the_target_filename() {
        let target: Option<&OsStr> = Some(OsStr::new("passwords.kdbx"));

        let matching = Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path(PathBuf::from("/tmp/sync/passwords.kdbx"));
        assert!(event_touches(&matching, target));

        let unrelated = Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any))
            .add_path(PathBuf::from("/tmp/sync/other-file.txt"));
        assert!(!event_touches(&unrelated, target));

        let pathless = Event::new(notify::EventKind::Modify(notify::event::ModifyKind::Any));
        assert!(event_touches(&pathless, target));
    }

    /// Drives the real filesystem watcher end-to-end. Not run by default
    /// (`cargo test`) since inotify/FSEvents availability and timing vary
    /// across sandboxes and CI runners; run explicitly with
    /// `cargo test -- --ignored` to verify the watcher works on a given
    /// machine.
    #[test]
    #[ignore]
    fn watch_and_merge_picks_up_an_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("local.kdbx");
        let other_path = dir.path().join("other.kdbx");
        let password = "watch_test_password_123";

        Vault::init(&vault_path, password).unwrap();

        std::fs::copy(&vault_path, &other_path).unwrap();
        let mut other_vault = Vault::unlock(&other_path, password).unwrap();
        let entry = PasswordEntry::new(
            "Test".to_string(),
            "https://test.com".to_string(),
            "user".to_string(),
            "pw".to_string(),
        );
        other_vault.add_entry(entry).unwrap();

        let (done_tx, done_rx) = mpsc::channel();
        let (v, o, p) = (vault_path.clone(), other_path.clone(), password.to_string());
        std::thread::spawn(move || {
            let result = watch_and_merge(&v, &o, &None, &p, 200, Some(1));
            let _ = done_tx.send(result);
        });

        // Give the watcher time to start before triggering the change it
        // should observe.
        std::thread::sleep(Duration::from_millis(300));
        other_vault.save(password).unwrap();

        // Generous timeout: run_merge derives an Argon2id key (deliberately
        // expensive: 64 MB / 3 iterations) up to three times per merge, on
        // top of whatever latency the filesystem watcher itself adds.
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("watcher did not react within 30s")
            .unwrap();

        let merged = Vault::unlock(&vault_path, password).unwrap();
        assert_eq!(merged.len(), 1);
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
    
    let master_password = prompt_master_password()?;
    let mut vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

    // Display header
    print_header(&vault, vault_path);

    // Main loop
    loop {
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
    vault.add_entry(entry)?;
    vault.save(master_password)?;

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

    vault.update_entry(&entry_id, Some(website), Some(url), Some(username), password)?;
    vault.save(master_password)?;

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
    vault.save(master_password)?;

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
