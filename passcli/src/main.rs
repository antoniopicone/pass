use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input, Password};
use passlib::{PasswordEntry, Vault};
use std::path::PathBuf;

const DEFAULT_VAULT_PATH: &str = "passwords.vault";

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

    /// Interactive mode - menu-driven interface for managing passwords
    Interactive,
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

/// Get a specific password entry
fn cmd_get(vault_path: &PathBuf, query: &str) -> Result<()> {
    let master_password = prompt_master_password()?;
    let vault = Vault::unlock(vault_path, &master_password)
        .context("Failed to unlock vault (wrong password?)")?;

    // Try to find by ID first, then by website name
    let entry = vault.get_entry(query)
        .or_else(|_| {
            // Search by website name
            let entries = vault.list_entries()?;
            let found = entries.iter()
                .find(|e| e.website.to_lowercase().contains(&query.to_lowercase()))
                .ok_or_else(|| passlib::PassError::EntryNotFound(query.to_string()))?;
            vault.get_entry(&found.id)
        })
        .context(format!("Entry not found: {}", query))?;

    println!();
    println!("{}", "🔑 Password Entry".bold().cyan());
    println!();
    println!("{}", "─".repeat(60).bright_black());
    println!("{}: {}", "Website".bold(), entry.website);
    println!("{}: {}", "URL".bold(), entry.url);
    println!("{}: {}", "Username".bold(), entry.username);
    println!("{}: {}", "Password".bold().green(), entry.password().green());
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
    println!("   Added:     {}", summary.added);
    println!("   Updated:   {}", summary.updated);
    println!("   Unchanged: {}", summary.unchanged);
    if summary.conflicts > 0 {
        println!(
            "   {}",
            format!(
                "Conflicts resolved: {} (most recently edited version kept)",
                summary.conflicts
            )
            .yellow()
        );
    }
    println!();

    Ok(())
}

/// Prompt for master password securely
fn prompt_master_password() -> Result<String> {
    Password::new()
        .with_prompt("Master password")
        .interact()
        .context("Failed to read master password")
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
    println!();
    println!("{}: {}", "Created".bright_black(), 
             entry.created_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!("{}: {}", "Updated".bright_black(), 
             entry.updated_at.format("%Y-%m-%d %H:%M").to_string().bright_black());
    println!();

    Ok(())
}
