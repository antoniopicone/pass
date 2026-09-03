//! `pass share` — give someone an entry, without a server.
//!
//! Bitwarden shares through an organisation the server owns. With no server
//! there is nothing to own a collection, so sharing here is a file: an
//! armored block sealed to one recipient's public key, which you send over
//! any channel you already use. See `docs/SYNC_STRATEGY.md` for how this fits
//! with syncing, and [`passlib::share`] for the construction.

use crate::access::AgentOrPrompt;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use dialoguer::Confirm;
use passlib::share::{self, ShareBundle, SharedEntry};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum ShareAction {
    /// Create this vault's sharing identity and print the public key to give
    /// to people who want to share with you
    Init {
        /// Name others will see this identity under
        #[arg(long)]
        label: Option<String>,
    },
    /// Print this vault's sharing public key
    Id,
    /// Remember someone's public key under a name
    Add {
        /// Name to remember them by
        label: String,
        /// Their `pass-share-pk1:…` public key
        public_key: String,
    },
    /// List remembered contacts
    Contacts,
    /// Forget a contact
    Forget {
        /// Contact name
        label: String,
    },
    /// Seal entries for a contact
    Export {
        /// Entries to share (name or id), repeatable
        #[arg(required = true)]
        entries: Vec<String>,
        /// Contact name, or a raw `pass-share-pk1:…` key
        #[arg(long)]
        to: String,
        /// Write to a file instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Open a bundle someone sent and add its entries to this vault
    Import {
        /// File containing the bundle (use `-` for stdin)
        file: PathBuf,
        /// Show what the bundle contains without adding anything
        #[arg(long)]
        dry_run: bool,

        /// Add without asking for confirmation (for scripts)
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

pub fn cmd_share(vault_path: &Path, action: ShareAction) -> Result<()> {
    let access = AgentOrPrompt::new(vault_path);

    match action {
        ShareAction::Init { label } => init(&access, label),
        ShareAction::Id => id(&access),
        ShareAction::Add { label, public_key } => add_contact(&access, &label, &public_key),
        ShareAction::Contacts => contacts(&access),
        ShareAction::Forget { label } => forget(&access, &label),
        ShareAction::Export { entries, to, out } => export(&access, &entries, &to, out.as_deref()),
        ShareAction::Import { file, dry_run, yes } => import(&access, &file, dry_run, yes),
    }
}

fn init(access: &AgentOrPrompt, label: Option<String>) -> Result<()> {
    let label = label.unwrap_or_else(default_label);
    let (mut vault, password) = access.open()?;

    let existed = vault.share_identity()?.is_some();
    let identity = vault.ensure_share_identity(&label)?;
    if !existed {
        vault.save(&password).context("Failed to save vault")?;
    }

    println!();
    if existed {
        println!("{}", "This vault already has a sharing identity.".yellow());
    } else {
        println!("{}", format!("✅ Sharing identity created for '{}'.", identity.label).green().bold());
    }
    println!();
    println!("Give this to anyone who wants to share an entry with you:");
    println!();
    println!("  {}", identity.public_key_string().cyan().bold());
    println!();
    println!(
        "{}",
        "It's a public key — safe to post anywhere. It is not a secret and grants no access."
            .bright_black()
    );
    println!();

    Ok(())
}

fn id(access: &AgentOrPrompt) -> Result<()> {
    let (vault, _) = access.open()?;
    let identity = vault
        .share_identity()?
        .ok_or_else(|| anyhow::anyhow!("No sharing identity yet. Create one with `pass share init`."))?;

    // Bare output: meant to be copied or piped.
    println!("{}", identity.public_key_string());
    Ok(())
}

fn add_contact(access: &AgentOrPrompt, label: &str, public_key: &str) -> Result<()> {
    let key = share::parse_public_key(public_key)?;
    let (mut vault, password) = access.open()?;

    // Remembering someone else's public key doesn't require having generated
    // your own, so create the identity on demand rather than refusing —
    // `share export` already works this way, and the contact list is stored
    // on the identity entry.
    vault.ensure_share_identity(&default_label())?;
    vault.add_share_contact(label, key)?;
    vault.save(&password).context("Failed to save vault")?;

    println!("{}", format!("✅ Contact '{label}' saved.").green().bold());
    Ok(())
}

fn contacts(access: &AgentOrPrompt) -> Result<()> {
    let (vault, _) = access.open()?;
    let contacts = vault.share_contacts();

    println!();
    if contacts.is_empty() {
        println!("{}", "No contacts yet.".yellow());
        println!("Add one with {}.", "pass share add <name> <public-key>".cyan());
    } else {
        println!("{}", format!("👥 Sharing contacts ({})", contacts.len()).bold().cyan());
        println!();
        for contact in contacts {
            println!("  {}", contact.label.bold());
            println!("    {}", contact.public_key_string().bright_black());
        }
    }
    println!();

    Ok(())
}

fn forget(access: &AgentOrPrompt, label: &str) -> Result<()> {
    let (mut vault, password) = access.open()?;

    if !vault.remove_share_contact(label)? {
        anyhow::bail!("No contact named '{label}'.");
    }
    vault.save(&password).context("Failed to save vault")?;

    println!("{}", format!("✅ Contact '{label}' forgotten.").green().bold());
    println!(
        "{}",
        "Anything already shared with them stays shared — rotate those passwords if that matters."
            .yellow()
    );
    Ok(())
}

fn export(access: &AgentOrPrompt, queries: &[String], to: &str, out: Option<&Path>) -> Result<()> {
    let (mut vault, password) = access.open()?;

    // Sharing needs our own identity to authenticate the bundle, so create
    // one on the fly rather than making the user run `init` first.
    let had_identity = vault.share_identity()?.is_some();
    let identity = vault.ensure_share_identity(&default_label())?;
    if !had_identity {
        vault.save(&password).context("Failed to save vault")?;
    }

    let recipient = resolve_recipient(&vault, to)?;

    let mut entries = Vec::new();
    for query in queries {
        let entry = crate::find_entry(&vault, query)?;
        entries.push(SharedEntry::from(&entry));
    }

    let bundle = ShareBundle::seal(&entries, &identity, recipient.key)?;
    let armored = bundle.to_armored()?;

    match out {
        Some(path) => {
            std::fs::write(path, &armored).with_context(|| format!("Failed to write {}", path.display()))?;
            eprintln!();
            eprintln!(
                "{}",
                format!("✅ Sealed {} entr{} for {} → {}",
                    entries.len(),
                    if entries.len() == 1 { "y" } else { "ies" },
                    recipient.name,
                    path.display()
                )
                .green()
                .bold()
            );
            eprintln!("{}", "   Send it however you like — it is useless to anyone else.".bright_black());
            eprintln!();
        }
        // To stdout, so it can be piped straight into an email or `wl-copy`.
        None => print!("{armored}"),
    }

    Ok(())
}

fn import(access: &AgentOrPrompt, file: &Path, dry_run: bool, yes: bool) -> Result<()> {
    let armored = if file == Path::new("-") {
        std::io::read_to_string(std::io::stdin()).context("Failed to read the bundle from stdin")?
    } else {
        std::fs::read_to_string(file).with_context(|| format!("Failed to read {}", file.display()))?
    };

    let bundle = ShareBundle::from_armored(&armored)?;
    let (mut vault, password) = access.open()?;

    let identity = vault.share_identity()?.ok_or_else(|| {
        anyhow::anyhow!("This vault has no sharing identity, so nothing can be sealed to it. Run `pass share init`.")
    })?;

    let (sender_key, entries) = bundle.open(&identity)?;
    let sender_name = vault
        .share_contacts()
        .into_iter()
        .find(|c| c.public_key_string() == sender_key)
        .map(|c| c.label);

    println!();
    match &sender_name {
        Some(name) => println!("{}", format!("📬 From {name}").bold().green()),
        // An unknown sender is not an error — someone can share with you
        // before you have added them — but it must be visibly unverified.
        None => {
            println!("{}", "📬 From an unknown sender".bold().yellow());
            println!("   {}", sender_key.bright_black());
            println!(
                "   {}",
                "Add them with `pass share add <name> <key>` to recognise them next time.".bright_black()
            );
        }
    }
    println!();
    println!("Contains {} entr{}:", entries.len(), if entries.len() == 1 { "y" } else { "ies" });
    for entry in &entries {
        println!("  • {} ({})", entry.website.bold(), entry.username);
    }
    println!();

    if dry_run {
        println!("{}", "Dry run — nothing was added.".bright_black());
        return Ok(());
    }

    if !yes
        && !Confirm::new()
            .with_prompt("Add these to your vault?")
            .default(true)
            .interact()
            .context("Failed to read confirmation")?
    {
        println!("{}", "Cancelled.".yellow());
        return Ok(());
    }

    let count = entries.len();
    for entry in entries {
        vault.add_entry(entry.into_password_entry()?)?;
    }
    vault.save(&password).context("Failed to save vault")?;

    println!();
    println!("{}", format!("✅ Added {count} entr{}.", if count == 1 { "y" } else { "ies" }).green().bold());
    println!();

    Ok(())
}

struct Recipient {
    name: String,
    key: [u8; 32],
}

/// Resolve `--to` as either a saved contact name or a raw public key.
fn resolve_recipient(vault: &passlib::Vault, to: &str) -> Result<Recipient> {
    if let Some(contact) = vault
        .share_contacts()
        .into_iter()
        .find(|c| c.label.eq_ignore_ascii_case(to))
    {
        return Ok(Recipient {
            name: contact.label,
            key: contact.public_key,
        });
    }

    match share::parse_public_key(to) {
        Ok(key) => Ok(Recipient {
            name: to.to_string(),
            key,
        }),
        Err(_) => anyhow::bail!(
            "No contact named '{to}', and it isn't a `pass-share-pk1:…` key either.\n\
             Add them first with `pass share add {to} <their-public-key>`."
        ),
    }
}

fn default_label() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "pass user".to_string())
}
