//! `pass type` — autotype credentials into whatever window has focus.
//!
//! For the applications that have no password-manager integration at all: a
//! VPN client, a VM console, an SSH session to a device with a web login, a
//! game launcher. You focus the window, run `pass type <entry>` (usually from
//! a global hotkey), and the credentials are typed as if from the keyboard.
//!
//! ## Why this shells out
//!
//! Synthesising key events is the one thing that is genuinely different on
//! every desktop: X11 has XTEST, Wayland deliberately does not (a client
//! cannot type into another client, by design) and routes it through a
//! portal or `uinput`, macOS has CGEvent, Windows has SendInput. Linking a
//! cross-platform input crate would add a C build dependency (`libxdo`) to
//! the whole CLI — so a machine without it could not build `pass` at all,
//! including its password manager — in exchange for a feature most users
//! never touch.
//!
//! Driving the tool the desktop already ships keeps that cost at zero and
//! fails with a message naming the package to install, rather than at
//! compile time on someone else's machine.
//!
//! ## What autotype cannot promise
//!
//! It types into whatever holds focus. If focus moves mid-sequence, the
//! password is typed into the wrong window. That is inherent to autotype in
//! every password manager, which is why the delay before typing is
//! configurable and why the default sequence ends with Enter only if asked.

use crate::access::AgentOrPrompt;
use anyhow::{Context, Result};
use colored::*;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// One step of an autotype sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Type a literal string (a username, a password, a TOTP code).
    Text(String),
    /// Press Tab, to move to the next field.
    Tab,
    /// Press Enter, to submit.
    Enter,
}

/// A backend able to synthesise keystrokes on this desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `wtype`, the Wayland virtual-keyboard tool.
    Wtype,
    /// `ydotool`, the uinput-based tool that works on Wayland compositors
    /// without the virtual-keyboard protocol (needs its daemon running).
    Ydotool,
    /// `xdotool`, on X11.
    Xdotool,
    /// AppleScript via `osascript`, on macOS.
    Osascript,
}

impl Backend {
    fn command(self) -> &'static str {
        match self {
            Backend::Wtype => "wtype",
            Backend::Ydotool => "ydotool",
            Backend::Xdotool => "xdotool",
            Backend::Osascript => "osascript",
        }
    }

    /// Install hint for when the tool is missing.
    fn install_hint(self) -> &'static str {
        match self {
            Backend::Wtype => "install `wtype` (most distributions package it under that name)",
            Backend::Ydotool => "install `ydotool` and start its daemon (`systemctl --user start ydotoold`)",
            Backend::Xdotool => "install `xdotool`",
            Backend::Osascript => "osascript ships with macOS; check Accessibility permissions in System Settings",
        }
    }
}

/// Pick a backend for this session, in the order most likely to work.
///
/// Session type comes from the environment rather than from probing, because
/// `xdotool` is often installed on a Wayland desktop (for XWayland apps) and
/// will appear to work while typing into nothing.
pub fn detect_backend(
    wayland_display: Option<&str>,
    x11_display: Option<&str>,
    target_os: &str,
    is_installed: &dyn Fn(&str) -> bool,
) -> Option<Backend> {
    if target_os == "macos" {
        return Some(Backend::Osascript);
    }

    let candidates: &[Backend] = match (wayland_display, x11_display) {
        (Some(_), _) => &[Backend::Wtype, Backend::Ydotool],
        (None, Some(_)) => &[Backend::Xdotool],
        // No graphical session at all: nothing to type into.
        (None, None) => &[],
    };

    candidates.iter().copied().find(|b| is_installed(b.command()))
}

/// Build the sequence for an entry: username, Tab, password, and optionally
/// Tab + the current MFA code, then optionally Enter.
pub fn build_sequence(
    username: &str,
    password: &str,
    totp_code: Option<&str>,
    password_only: bool,
    submit: bool,
) -> Vec<Step> {
    let mut steps = Vec::new();

    if !password_only && !username.is_empty() {
        steps.push(Step::Text(username.to_string()));
        steps.push(Step::Tab);
    }
    steps.push(Step::Text(password.to_string()));

    if let Some(code) = totp_code {
        steps.push(Step::Tab);
        steps.push(Step::Text(code.to_string()));
    }
    if submit {
        steps.push(Step::Enter);
    }

    steps
}

pub struct TypeOptions {
    pub password_only: bool,
    pub with_totp: bool,
    pub submit: bool,
    pub delay: Duration,
    pub dry_run: bool,
}

pub fn cmd_type(vault_path: &Path, query: &str, options: &TypeOptions) -> Result<()> {
    let access = AgentOrPrompt::new(vault_path);
    let entry = access.entry(query)?;

    let totp = options.with_totp.then(|| entry.totp_code.clone()).flatten();
    if options.with_totp && totp.is_none() {
        anyhow::bail!("`{}` has no MFA secret, so --with-totp has nothing to type", entry.website);
    }

    let steps = build_sequence(
        &entry.username,
        &entry.password,
        totp.as_deref(),
        options.password_only,
        options.submit,
    );

    if options.dry_run {
        // Never print the secrets themselves — the whole point of autotype is
        // that they don't pass through a terminal.
        println!("{}", "Would type (secrets redacted):".bold());
        for step in &steps {
            println!("  {}", describe(step).bright_black());
        }
        return Ok(());
    }

    let backend = detect_backend(
        std::env::var("WAYLAND_DISPLAY").ok().as_deref(),
        std::env::var("DISPLAY").ok().as_deref(),
        std::env::consts::OS,
        &|command| which(command),
    )
    .ok_or_else(autotype_unavailable_error)?;

    eprintln!(
        "{}",
        format!(
            "⌨️  Typing '{}' via {} in {:?} — focus the target window now.",
            entry.website,
            backend.command(),
            options.delay
        )
        .bright_black()
    );
    std::thread::sleep(options.delay);

    for step in &steps {
        run_step(backend, step)
            .with_context(|| format!("Autotype failed at step: {}", describe(step)))?;
        // A short gap between steps: applications that move focus on Tab
        // routinely drop input sent in the same instant.
        std::thread::sleep(Duration::from_millis(40));
    }

    eprintln!("{}", "✅ Typed.".green());
    Ok(())
}

fn describe(step: &Step) -> String {
    match step {
        Step::Text(text) => format!("type <{} characters>", text.chars().count()),
        Step::Tab => "press Tab".to_string(),
        Step::Enter => "press Enter".to_string(),
    }
}

fn run_step(backend: Backend, step: &Step) -> Result<()> {
    let status = match (backend, step) {
        (Backend::Wtype, Step::Text(text)) => Command::new("wtype").arg("--").arg(text).status(),
        (Backend::Wtype, Step::Tab) => Command::new("wtype").args(["-k", "Tab"]).status(),
        (Backend::Wtype, Step::Enter) => Command::new("wtype").args(["-k", "Return"]).status(),

        (Backend::Ydotool, Step::Text(text)) => Command::new("ydotool").arg("type").arg("--").arg(text).status(),
        (Backend::Ydotool, Step::Tab) => Command::new("ydotool").args(["key", "15:1", "15:0"]).status(),
        (Backend::Ydotool, Step::Enter) => Command::new("ydotool").args(["key", "28:1", "28:0"]).status(),

        (Backend::Xdotool, Step::Text(text)) => {
            Command::new("xdotool").args(["type", "--clearmodifiers", "--"]).arg(text).status()
        }
        (Backend::Xdotool, Step::Tab) => Command::new("xdotool").args(["key", "Tab"]).status(),
        (Backend::Xdotool, Step::Enter) => Command::new("xdotool").args(["key", "Return"]).status(),

        (Backend::Osascript, step) => Command::new("osascript").args(["-e", &applescript(step)]).status(),
    }
    .with_context(|| {
        format!(
            "could not run `{}` — {}",
            backend.command(),
            backend.install_hint()
        )
    })?;

    if !status.success() {
        anyhow::bail!("`{}` exited with {}", backend.command(), status);
    }
    Ok(())
}

fn applescript(step: &Step) -> String {
    match step {
        // AppleScript string literals escape backslash and double quote only.
        Step::Text(text) => {
            let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
            format!(r#"tell application "System Events" to keystroke "{escaped}""#)
        }
        Step::Tab => r#"tell application "System Events" to key code 48"#.to_string(),
        Step::Enter => r#"tell application "System Events" to key code 36"#.to_string(),
    }
}

fn which(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(command).is_file())
}

fn autotype_unavailable_error() -> anyhow::Error {
    anyhow::anyhow!(
        "No autotype backend available.\n\
         \n\
         On Wayland: {}\n\
         On X11:     {}\n\
         \n\
         Or use `pass get <entry>` and copy the password by hand.",
        Backend::Wtype.install_hint(),
        Backend::Xdotool.install_hint(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_installed(_: &str) -> bool {
        true
    }
    fn none_installed(_: &str) -> bool {
        false
    }

    #[test]
    fn wayland_prefers_wtype_over_xdotool() {
        // The bug this guards: `xdotool` is usually installed on a Wayland
        // desktop for XWayland apps, and picking it would type into nothing.
        let backend = detect_backend(Some("wayland-0"), Some(":0"), "linux", &all_installed);
        assert_eq!(backend, Some(Backend::Wtype));
    }

    #[test]
    fn wayland_falls_back_to_ydotool_when_wtype_is_missing() {
        let backend = detect_backend(Some("wayland-0"), None, "linux", &|c| c == "ydotool");
        assert_eq!(backend, Some(Backend::Ydotool));
    }

    #[test]
    fn x11_uses_xdotool() {
        let backend = detect_backend(None, Some(":0"), "linux", &all_installed);
        assert_eq!(backend, Some(Backend::Xdotool));
    }

    #[test]
    fn macos_always_has_a_backend() {
        assert_eq!(
            detect_backend(None, None, "macos", &none_installed),
            Some(Backend::Osascript)
        );
    }

    #[test]
    fn a_headless_session_has_no_backend() {
        assert_eq!(detect_backend(None, None, "linux", &all_installed), None);
    }

    #[test]
    fn a_graphical_session_without_the_tools_has_no_backend() {
        assert_eq!(detect_backend(Some("wayland-0"), None, "linux", &none_installed), None);
        assert_eq!(detect_backend(None, Some(":0"), "linux", &none_installed), None);
    }

    #[test]
    fn the_default_sequence_is_username_tab_password() {
        assert_eq!(
            build_sequence("me@example.com", "s3cret", None, false, false),
            vec![
                Step::Text("me@example.com".to_string()),
                Step::Tab,
                Step::Text("s3cret".to_string()),
            ]
        );
    }

    #[test]
    fn password_only_skips_the_username() {
        assert_eq!(
            build_sequence("me", "s3cret", None, true, false),
            vec![Step::Text("s3cret".to_string())]
        );
    }

    #[test]
    fn an_entry_without_a_username_types_only_the_password() {
        assert_eq!(
            build_sequence("", "s3cret", None, false, false),
            vec![Step::Text("s3cret".to_string())],
            "a leading Tab would land in the wrong field"
        );
    }

    #[test]
    fn totp_and_submit_are_appended_in_order() {
        assert_eq!(
            build_sequence("me", "pw", Some("123456"), false, true),
            vec![
                Step::Text("me".to_string()),
                Step::Tab,
                Step::Text("pw".to_string()),
                Step::Tab,
                Step::Text("123456".to_string()),
                Step::Enter,
            ]
        );
    }

    #[test]
    fn describing_a_step_never_reveals_the_text() {
        let description = describe(&Step::Text("hunter2".to_string()));
        assert!(!description.contains("hunter2"), "dry-run leaked a secret: {description}");
        assert!(description.contains('7'), "expected a character count: {description}");
    }

    #[test]
    fn applescript_escapes_quotes_and_backslashes() {
        // An unescaped quote would end the AppleScript string early and turn
        // the rest of the password into code.
        let script = applescript(&Step::Text(r#"pass"word\x"#.to_string()));
        assert!(script.contains(r#"pass\"word\\x"#), "bad escaping: {script}");
    }
}
