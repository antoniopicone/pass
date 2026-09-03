//! Where the agent's sockets live, and how they are protected.
//!
//! The security model is OpenSSH's own: the sockets sit in a directory only
//! the owning user can enter (`0700`), and the sockets themselves are `0600`.
//! Anyone who can bypass that — root, or the user themselves — could equally
//! read the process's memory, so no additional handshake would buy anything.
//!
//! `$XDG_RUNTIME_DIR` is preferred because it is per-user, already `0700`,
//! and cleared at logout, which means a stale socket cannot outlive a
//! session. Where it doesn't exist (macOS, most notably) we fall back to a
//! per-uid directory under the system temp directory.

use std::io;
use std::path::PathBuf;

/// Environment variable overriding the control socket path.
pub const IPC_SOCKET_ENV: &str = "PASS_AGENT_SOCK";
/// Environment variable overriding the SSH agent socket path.
pub const SSH_SOCKET_ENV: &str = "PASS_SSH_AUTH_SOCK";

/// Directory holding this user's agent sockets, created `0700` if needed.
pub fn runtime_dir() -> io::Result<PathBuf> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        // No per-user runtime directory: fall back to the temp directory,
        // namespaced by uid so two users on one machine cannot collide (or
        // squat on each other's path).
        _ => std::env::temp_dir().join(format!("pass-{}", current_uid())),
    };

    let dir = base.join("pass");
    std::fs::create_dir_all(&dir)?;
    restrict_to_owner(&dir, 0o700)?;
    Ok(dir)
}

/// Environment variable overriding where sync state is kept.
pub const STATE_DIR_ENV: &str = "PASS_STATE_DIR";

/// Directory holding state that must outlive a login session, created
/// `0700` if needed.
///
/// Deliberately *not* [`runtime_dir`]: `$XDG_RUNTIME_DIR` is cleared at
/// logout, which is exactly right for a socket and exactly wrong for the
/// sync op-log — losing it every time the user logs out would make every
/// peer re-send its whole history on the next login.
pub fn state_dir() -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(STATE_DIR_ENV).filter(|d| !d.is_empty()) {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)?;
        restrict_to_owner(&dir, 0o700)?;
        return Ok(dir);
    }

    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => home_dir()?.join(".local").join("state"),
    };

    let dir = base.join("pass");
    std::fs::create_dir_all(&dir)?;
    restrict_to_owner(&dir, 0o700)?;
    Ok(dir)
}

fn home_dir() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))
}

/// Path of the agent's control socket (the one the `pass` CLI talks to).
pub fn ipc_socket_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os(IPC_SOCKET_ENV) {
        return Ok(PathBuf::from(path));
    }
    Ok(runtime_dir()?.join("agent.sock"))
}

/// Path of the SSH agent socket (the one `SSH_AUTH_SOCK` should point at).
pub fn ssh_agent_socket_path() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os(SSH_SOCKET_ENV) {
        return Ok(PathBuf::from(path));
    }
    Ok(runtime_dir()?.join("ssh-agent.sock"))
}

/// Tighten a path's permissions to the owner only.
///
/// A no-op on Windows, where the equivalent is an ACL rather than a mode;
/// the agent's Unix-socket transport doesn't run there anyway.
pub fn restrict_to_owner(path: &std::path::Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` takes no arguments, cannot fail, and has no side
    // effects beyond reading the calling process's own uid.
    unsafe { libc::getuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides_win() {
        // Set/read in one test rather than two: environment variables are
        // process-global and Rust runs tests in parallel threads.
        let ipc = std::env::temp_dir().join("custom-agent.sock");
        let ssh = std::env::temp_dir().join("custom-ssh.sock");

        std::env::set_var(IPC_SOCKET_ENV, &ipc);
        std::env::set_var(SSH_SOCKET_ENV, &ssh);

        assert_eq!(ipc_socket_path().unwrap(), ipc);
        assert_eq!(ssh_agent_socket_path().unwrap(), ssh);

        std::env::remove_var(IPC_SOCKET_ENV);
        std::env::remove_var(SSH_SOCKET_ENV);
    }

    #[cfg(unix)]
    #[test]
    fn the_runtime_directory_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = runtime_dir().unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "runtime dir {} is not 0700", dir.display());
    }

    #[test]
    fn the_state_directory_is_private_and_honours_its_override() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("state");
        std::env::set_var(STATE_DIR_ENV, &custom);
        let resolved = state_dir().unwrap();
        std::env::remove_var(STATE_DIR_ENV);

        assert_eq!(resolved, custom);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&resolved).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "sync state would be world-readable");
        }
    }

    #[test]
    fn the_two_sockets_are_distinct() {
        assert_ne!(ipc_socket_path().unwrap(), ssh_agent_socket_path().unwrap());
    }
}
