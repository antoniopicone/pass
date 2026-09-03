//! `pass run` — inject secrets into a command's environment.
//!
//! The problem this solves: an API key needed by a script ends up in
//! `.env`, in shell history, or exported into every process you start.
//! `pass run` puts it in exactly one process's environment, for exactly as
//! long as that process runs:
//!
//! ```text
//! pass run --secret STRIPE_KEY=stripe -- ./deploy.sh
//! ```
//!
//! ## What this does not protect against
//!
//! On Linux any process running as you can read `/proc/<pid>/environ` of your
//! own processes, and a child inherits the variable. This is not a
//! confidentiality boundary against your own account — it is a way to keep
//! secrets out of *files*, shell history, and long-lived shell environments,
//! which is where they actually leak from.

use crate::access::AgentOrPrompt;
use anyhow::{Context, Result};
use colored::*;
use std::path::Path;
use std::process::Command;

/// Which part of an entry to inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Password,
    Username,
    Totp,
    Notes,
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "password" | "pass" => Some(Field::Password),
            "username" | "user" => Some(Field::Username),
            "totp" | "otp" | "mfa" => Some(Field::Totp),
            "notes" | "note" => Some(Field::Notes),
            _ => None,
        }
    }
}

/// One `VAR=entry[:field]` mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretSpec {
    variable: String,
    query: String,
    field: Field,
}

/// Parse `VAR=entry` or `VAR=entry:field`.
///
/// The entry query is allowed to contain `:` (a URL, typically), so the field
/// is taken from the *last* colon and only when what follows it is a field
/// name we recognise — `GH=https://github.com` must not be read as the
/// `//github.com` field of an entry called `https`.
fn parse_spec(raw: &str) -> Result<SecretSpec> {
    let (variable, target) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected VAR=entry[:field], got `{raw}`"))?;

    if variable.is_empty() {
        anyhow::bail!("missing variable name in `{raw}`");
    }
    if target.is_empty() {
        anyhow::bail!("missing entry name in `{raw}`");
    }

    let (query, field) = match target.rsplit_once(':') {
        Some((query, suffix)) => match Field::parse(suffix) {
            Some(field) if !query.is_empty() => (query, field),
            _ => (target, Field::Password),
        },
        None => (target, Field::Password),
    };

    Ok(SecretSpec {
        variable: variable.to_string(),
        query: query.to_string(),
        field,
    })
}

pub fn cmd_run(vault_path: &Path, secrets: &[String], command: &[String]) -> Result<()> {
    let Some((program, args)) = command.split_first() else {
        anyhow::bail!("No command given. Usage: pass run --secret VAR=entry -- <command> [args...]");
    };

    let specs: Vec<SecretSpec> = secrets.iter().map(|s| parse_spec(s)).collect::<Result<_>>()?;
    if specs.is_empty() {
        anyhow::bail!("No secrets to inject. Pass at least one --secret VAR=entry.");
    }

    let access = AgentOrPrompt::new(vault_path);
    let mut child = Command::new(program);
    child.args(args);

    for spec in &specs {
        let entry = access
            .entry(&spec.query)
            .with_context(|| format!("Failed to resolve `{}` for ${}", spec.query, spec.variable))?;

        let value = match spec.field {
            Field::Password => entry.password.clone(),
            Field::Username => entry.username.clone(),
            Field::Notes => entry.notes.clone(),
            Field::Totp => entry.totp_code.clone().ok_or_else(|| {
                anyhow::anyhow!("`{}` has no MFA secret, so ${} cannot be set", spec.query, spec.variable)
            })?,
        };

        child.env(&spec.variable, value);
    }

    // Progress goes to stderr so it can't corrupt a piped stdout.
    eprintln!(
        "{}",
        format!(
            "🔐 Running `{}` with {} injected.",
            program,
            specs.iter().map(|s| s.variable.as_str()).collect::<Vec<_>>().join(", ")
        )
        .bright_black()
    );

    let status = child
        .status()
        .with_context(|| format!("Failed to run `{program}`"))?;

    // Propagate the child's exit code, so `pass run` is transparent in a
    // script or a CI step rather than always reporting success.
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_spec_defaults_to_the_password() {
        assert_eq!(
            parse_spec("STRIPE_KEY=stripe").unwrap(),
            SecretSpec {
                variable: "STRIPE_KEY".to_string(),
                query: "stripe".to_string(),
                field: Field::Password,
            }
        );
    }

    #[test]
    fn an_explicit_field_is_honoured() {
        for (raw, expected) in [
            ("U=github:username", Field::Username),
            ("P=github:password", Field::Password),
            ("T=github:totp", Field::Totp),
            ("N=github:notes", Field::Notes),
            ("U=github:USER", Field::Username),
        ] {
            assert_eq!(parse_spec(raw).unwrap().field, expected, "for {raw}");
        }
    }

    #[test]
    fn a_url_entry_is_not_mistaken_for_a_field() {
        // The regression this guards: splitting on the last colon
        // unconditionally would turn this into entry `https://github.com`
        // field `8080`, or worse, entry `https` field `//github.com`.
        let spec = parse_spec("GH=https://github.com").unwrap();
        assert_eq!(spec.query, "https://github.com");
        assert_eq!(spec.field, Field::Password);

        let spec = parse_spec("GH=https://github.com:8080").unwrap();
        assert_eq!(spec.query, "https://github.com:8080");
        assert_eq!(spec.field, Field::Password);
    }

    #[test]
    fn a_url_entry_can_still_ask_for_a_field() {
        let spec = parse_spec("U=https://github.com:username").unwrap();
        assert_eq!(spec.query, "https://github.com");
        assert_eq!(spec.field, Field::Username);
    }

    #[test]
    fn malformed_specs_are_rejected_with_a_useful_message() {
        for raw in ["no-equals-sign", "=missing-variable", "MISSING_ENTRY="] {
            let error = parse_spec(raw).unwrap_err().to_string();
            assert!(!error.is_empty(), "no message for {raw}");
        }

        assert!(parse_spec("VAR=entry").is_ok());
    }

    #[test]
    fn a_lone_colon_entry_is_not_split_into_an_empty_query() {
        let spec = parse_spec("V=:password").unwrap();
        assert_eq!(spec.query, ":password", "an empty query would match every entry");
    }
}
