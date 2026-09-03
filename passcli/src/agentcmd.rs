//! `pass agent`, `pass unlock`, `pass lock`, `pass status`.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::*;
use crate::access::prompt_secret;
use pass_agent::sync::{SyncConfig, AGENT_PORT};
use pass_agent::{Agent, Client};
use std::path::Path;
use std::time::Duration;

#[derive(Subcommand)]
pub enum AgentAction {
    /// Run the agent in the foreground (put it under systemd/launchd to keep
    /// it running)
    Run {
        /// Auto-lock the vault after this many minutes of inactivity; 0 to
        /// never auto-lock
        #[arg(long, default_value_t = 15)]
        idle_minutes: u64,
        /// Also replicate this vault to your other devices (see `pass sync`)
        #[arg(long)]
        sync: bool,
        /// Port the sync node listens on
        #[arg(long, default_value_t = AGENT_PORT, requires = "sync")]
        sync_port: u16,
        /// Address to bind. Defaults to this machine's tailnet address, and
        /// to loopback when there is no tailnet — deliberately not every
        /// interface
        #[arg(long, requires = "sync")]
        sync_bind: Option<String>,
        /// `host:port` to announce to peers. Defaults to the tailnet address
        #[arg(long, requires = "sync")]
        sync_advertise: Option<String>,
        /// A peer to try before anything has been discovered, repeatable
        #[arg(long, value_name = "HOST:PORT", requires = "sync")]
        sync_peer: Vec<String>,
        /// Seconds between reconciliation rounds
        #[arg(long, default_value_t = 30, requires = "sync")]
        sync_interval: u64,
    },
    /// Show whether an agent is running and what it is holding
    Status,
    /// Stop the running agent, locking the vault
    Stop,
    /// Print the shell line that points SSH at this agent
    Env,
}

pub fn cmd_agent(action: AgentAction) -> Result<()> {
    match action {
        AgentAction::Run {
            idle_minutes,
            sync,
            sync_port,
            sync_bind,
            sync_advertise,
            sync_peer,
            sync_interval,
        } => run(
            idle_minutes,
            sync.then(|| SyncConfig {
                port: sync_port,
                bind: sync_bind,
                advertise: sync_advertise,
                bootstrap: sync_peer,
                interval: Duration::from_secs(sync_interval.max(1)),
            }),
        ),
        AgentAction::Status => status(),
        AgentAction::Stop => stop(),
        AgentAction::Env => env(),
    }
}

fn run(idle_minutes: u64, sync: Option<SyncConfig>) -> Result<()> {
    let mut agent = Agent::with_default_paths().context("Failed to determine agent socket paths")?;
    let sync_summary = match sync {
        Some(config) => {
            let listening = format!("{}:{}", config.bind_address(), config.port);
            let advertise = config.advertise_address();
            match agent.enable_sync(config) {
                Ok(()) => Some((listening, advertise)),
                Err(e) => {
                    // Said loudly and then survived. The most likely cause is
                    // a sync state file that will not parse, and the agent's
                    // first job — holding the vault open and answering `ssh`
                    // — must not go down with it.
                    eprintln!("{} {e}", "⚠  Sync not started:".yellow().bold());
                    eprintln!("   The agent is running without it.");
                    eprintln!(
                        "   If the sync state is damaged, delete it and let the peers re-send: {}",
                        "rm \"$XDG_STATE_HOME/pass/sync-state.json\"".cyan()
                    );
                    eprintln!();
                    None
                }
            }
        }
        None => None,
    };

    println!("{}", "🔑 pass agent".bold().cyan());
    println!("   Control socket: {}", agent.ipc_path().display());
    println!("   SSH agent socket: {}", agent.ssh_path().display());
    println!();
    println!("   Point SSH at it with:");
    println!("     {}", format!("export SSH_AUTH_SOCK={}", agent.ssh_path().display()).cyan());
    println!();
    if idle_minutes == 0 {
        println!("   {}", "Auto-lock disabled — the vault stays unlocked until you lock it.".yellow());
    } else {
        println!("   Auto-locks after {idle_minutes} minutes idle.");
    }
    if let Some((listening, advertise)) = &sync_summary {
        println!("   Sync: listening on {}", listening.cyan());
        if advertise.is_empty() {
            println!("         {}", "no address to announce — this node calls out, nobody calls in".dimmed());
        } else {
            println!("         announcing {advertise}");
        }
        println!("         Pair devices with {}.", "pass sync trust".cyan());
        println!();
    }
    println!("   Unlock it from another terminal with {}.", "pass unlock".cyan());
    println!("   Press Ctrl+C to stop.");
    println!();

    agent.run().context("Agent stopped with an error")
}

fn status() -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;

    if !client.is_running() {
        println!("{}", "🔒 No agent running.".yellow());
        println!("   Start one with {}.", "pass agent run".cyan());
        return Ok(());
    }

    let status = client.status().map_err(|e| anyhow::anyhow!(e))?;

    if status.unlocked {
        println!("{}", "🔓 Vault unlocked".green().bold());
        if let Some(vault) = &status.vault {
            println!("   Vault: {}", vault.display());
        }
        match status.locks_in_secs {
            Some(0) => println!("   Auto-lock: {}", "disabled".yellow()),
            Some(secs) => println!("   Locks in: {}m {}s", secs / 60, secs % 60),
            None => {}
        }
        println!("   SSH keys served: {}", status.ssh_keys);
    } else {
        println!("{}", "🔒 Agent running, vault locked".yellow().bold());
        println!("   Unlock with {}.", "pass unlock".cyan());
    }
    println!("   SSH_AUTH_SOCK: {}", status.ssh_auth_sock.display());

    Ok(())
}

fn stop() -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    if !client.is_running() {
        println!("{}", "No agent running.".yellow());
        return Ok(());
    }

    client.shutdown().map_err(|e| anyhow::anyhow!(e))?;
    println!("{}", "✅ Agent stopped, vault locked.".green().bold());
    Ok(())
}

fn env() -> Result<()> {
    let path = pass_agent::paths::ssh_agent_socket_path().context("Failed to determine SSH agent socket path")?;
    // Bare, machine-readable output: this is meant for `eval "$(pass agent env)"`.
    println!("export SSH_AUTH_SOCK={}", path.display());
    Ok(())
}

/// `pass unlock` — hand the master password to the agent once.
pub fn cmd_unlock(vault_path: &Path, idle_minutes: Option<u64>) -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    if !client.is_running() {
        anyhow::bail!(
            "No agent is running. Start one with `pass agent run` (or a systemd user service) first."
        );
    }

    if !vault_path.exists() {
        anyhow::bail!("Vault file not found: {}", vault_path.display());
    }

    let master_password = prompt_secret("Master password")?;

    let timeout = idle_minutes.map(|m| Duration::from_secs(m * 60));
    client
        .unlock(vault_path, &master_password, timeout)
        .map_err(|e| anyhow::anyhow!(e))?;

    let status = client.status().map_err(|e| anyhow::anyhow!(e))?;

    println!();
    println!("{}", "✅ Vault unlocked.".green().bold());
    println!("   SSH keys now served: {}", status.ssh_keys);
    match status.locks_in_secs {
        Some(0) => println!("   {}", "Auto-lock disabled.".yellow()),
        Some(secs) => println!("   Auto-locks after {} minutes idle.", secs / 60),
        None => {}
    }
    println!();

    Ok(())
}

/// `pass lock` — wipe the agent's session now.
pub fn cmd_lock() -> Result<()> {
    let client = Client::with_default_path().context("Failed to determine agent socket path")?;
    if !client.is_running() {
        println!("{}", "No agent running — nothing to lock.".yellow());
        return Ok(());
    }

    client.lock().map_err(|e| anyhow::anyhow!(e))?;
    println!("{}", "🔒 Vault locked.".green().bold());
    Ok(())
}
