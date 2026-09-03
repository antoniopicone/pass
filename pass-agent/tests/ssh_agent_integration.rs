//! End-to-end tests for the agent, including against the real OpenSSH client.
//!
//! The unit tests in `sshagent` prove the codec matches the specification as
//! written; these prove the specification was read correctly, by pointing
//! `ssh-add` — the actual program users will run — at a live agent and
//! checking what it reports. A protocol bug that both our encoder and our
//! decoder agree on is exactly the kind that only this test catches.


use pass_agent::sshagent;
use pass_agent::{Agent, Client};
use passlib::{SshKey, Vault};
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const MASTER_PASSWORD: &str = "integration-test-master-password";

/// A running agent with a vault behind it, shut down on drop.
struct TestAgent {
    _dir: tempfile::TempDir,
    vault_path: PathBuf,
    client: Client,
    ssh_sock: PathBuf,
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestAgent {
    fn start(keys: &[SshKey]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault_path = dir.path().join("vault.kdbx");

        let mut vault = Vault::init(&vault_path, MASTER_PASSWORD).unwrap();
        for key in keys {
            vault.add_ssh_key(key).unwrap();
        }

        // One password entry, with an MFA secret, so the control-socket tests
        // have something real to read back.
        let mut entry = passlib::PasswordEntry::new(
            "GitHub".to_string(),
            "https://github.com".to_string(),
            "me@example.com".to_string(),
            "the-github-password".to_string(),
        );
        entry.totp = Some(
            passlib::totp::parse_otpauth_uri("otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap(),
        );
        vault.add_entry(entry).unwrap();
        vault.save(MASTER_PASSWORD).unwrap();

        // Sockets go in the temp dir, not the real runtime dir, so a test run
        // can never collide with the user's own agent.
        let ipc_sock = dir.path().join("agent.sock");
        let ssh_sock = dir.path().join("ssh-agent.sock");

        let agent = Agent::new(ipc_sock.clone(), ssh_sock.clone());
        let shutdown = agent.shutdown_handle();
        let thread = std::thread::spawn(move || {
            agent.run().unwrap();
        });

        let client = Client::new(ipc_sock);
        wait_until(|| client.is_running(), "the agent never started listening");

        Self {
            _dir: dir,
            vault_path,
            client,
            ssh_sock,
            shutdown,
            thread: Some(thread),
        }
    }

    fn unlock(&self) {
        self.client
            .unlock(&self.vault_path, MASTER_PASSWORD, Some(Duration::from_secs(300)))
            .unwrap();
    }

    /// Run `ssh-add` against this agent's socket.
    fn ssh_add(&self, args: &[&str]) -> std::process::Output {
        Command::new("ssh-add")
            .args(args)
            .env("SSH_AUTH_SOCK", &self.ssh_sock)
            .output()
            .expect("failed to run ssh-add")
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_until(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{message}");
}

/// `ssh-add` is not guaranteed to be installed everywhere this test suite
/// runs; skip rather than fail where it isn't.
fn have_ssh_add() -> bool {
    Command::new("ssh-add").arg("-l").output().is_ok()
}

#[test]
fn real_ssh_add_lists_the_vaults_keys() {
    if !have_ssh_add() {
        eprintln!("skipping: ssh-add is not installed");
        return;
    }

    let laptop = SshKey::generate("laptop", "antonio@laptop").unwrap();
    let deploy = SshKey::generate("deploy", "ci@example.com").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&laptop));

    // Locked: `ssh-add -l` must report an empty agent (exit status 1), not an
    // error, so `ssh` falls through to its next auth method.
    let locked = agent.ssh_add(&["-l"]);
    let locked_output = String::from_utf8_lossy(&locked.stdout);
    assert!(
        locked_output.contains("no identities"),
        "a locked agent should look empty, got: {locked_output}{}",
        String::from_utf8_lossy(&locked.stderr)
    );

    agent.unlock();

    let listed = agent.ssh_add(&["-l"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        listed.status.success(),
        "ssh-add -l failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );

    // `ssh-add -l` prints `<bits> <fingerprint> <comment> (<type>)`. The
    // fingerprint is computed by OpenSSH from the blob we sent, so matching it
    // proves the public key blob went over the wire intact.
    assert!(
        stdout.contains(&laptop.fingerprint),
        "ssh-add did not report the key's fingerprint.\nexpected: {}\ngot: {stdout}",
        laptop.fingerprint
    );
    assert!(stdout.contains("antonio@laptop"), "comment missing from: {stdout}");
    assert!(!stdout.contains(&deploy.fingerprint), "reported a key not in the vault");
}

#[test]
fn real_ssh_add_prints_public_keys_that_match_the_vault() {
    if !have_ssh_add() {
        eprintln!("skipping: ssh-add is not installed");
        return;
    }

    let key = SshKey::generate("laptop", "antonio@laptop").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    agent.unlock();

    // `ssh-add -L` re-encodes the blob into an authorized_keys line. If our
    // blob encoding were wrong in any way OpenSSH tolerates on input, this is
    // where it would show up as a different line.
    let output = agent.ssh_add(&["-L"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    let printed = stdout.lines().next().expect("ssh-add -L printed nothing");
    let printed_key: Vec<&str> = printed.split_whitespace().take(2).collect();
    let expected_key: Vec<&str> = key.public_key.split_whitespace().take(2).collect();

    assert_eq!(
        printed_key, expected_key,
        "ssh-add -L printed a different public key than the vault holds"
    );
}

#[test]
fn locking_the_session_takes_the_keys_away_from_ssh() {
    if !have_ssh_add() {
        eprintln!("skipping: ssh-add is not installed");
        return;
    }

    let key = SshKey::generate("laptop", "antonio@laptop").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    agent.unlock();
    assert!(String::from_utf8_lossy(&agent.ssh_add(&["-l"]).stdout).contains(&key.fingerprint));

    agent.client.lock().unwrap();

    let after = String::from_utf8_lossy(&agent.ssh_add(&["-l"]).stdout).to_string();
    assert!(
        !after.contains(&key.fingerprint),
        "the key was still served after locking: {after}"
    );
}

#[test]
fn the_agent_refuses_to_let_ssh_add_write_to_it() {
    if !have_ssh_add() {
        eprintln!("skipping: ssh-add is not installed");
        return;
    }

    let key = SshKey::generate("laptop", "antonio@laptop").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    agent.unlock();

    // Deleting all identities must fail: keys live in the vault, and an agent
    // that let `ssh-add -D` empty it would be lying about where they are.
    let deleted = agent.ssh_add(&["-D"]);
    assert!(!deleted.status.success(), "ssh-add -D was allowed to wipe the agent");

    // ...and the key is still there afterwards.
    assert!(String::from_utf8_lossy(&agent.ssh_add(&["-l"]).stdout).contains(&key.fingerprint));
}

/// Drive a signature over the raw protocol and verify it against the public
/// key, which is what an SSH *server* would do with the same bytes.
#[test]
fn a_signature_from_the_agent_verifies_against_the_public_key() {
    use signature::Verifier;

    let key = SshKey::generate("laptop", "antonio@laptop").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    agent.unlock();

    let blob = key.public_key_blob().unwrap();
    let data = b"the session identifier and everything else ssh signs";

    let mut request = vec![sshagent::SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut request, &blob);
    put_string(&mut request, data);
    request.extend_from_slice(&0u32.to_be_bytes());

    let response = ssh_roundtrip(&agent.ssh_sock, &request);
    assert_eq!(response[0], sshagent::SSH_AGENT_SIGN_RESPONSE, "agent refused to sign");

    // Response is: byte type, string signature-blob.
    let signature_blob = read_string(&response[1..]).expect("malformed sign response");
    let signature = ssh_key::Signature::try_from(signature_blob).unwrap();
    let public = ssh_key::PublicKey::from_openssh(&key.public_key).unwrap();

    Verifier::verify(&public, data, &signature).expect("the agent's signature does not verify");
}

#[test]
fn a_signature_request_for_an_unknown_key_is_refused() {
    let known = SshKey::generate("known", "a@a").unwrap();
    let stranger = SshKey::generate("stranger", "b@b").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&known));
    agent.unlock();

    let mut request = vec![sshagent::SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut request, &stranger.public_key_blob().unwrap());
    put_string(&mut request, b"data");
    request.extend_from_slice(&0u32.to_be_bytes());

    let response = ssh_roundtrip(&agent.ssh_sock, &request);
    assert_eq!(response, vec![sshagent::SSH_AGENT_FAILURE]);
}

#[test]
fn a_locked_agent_signs_nothing() {
    let key = SshKey::generate("laptop", "a@a").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    // Deliberately not unlocked.

    let mut request = vec![sshagent::SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut request, &key.public_key_blob().unwrap());
    put_string(&mut request, b"data");
    request.extend_from_slice(&0u32.to_be_bytes());

    let response = ssh_roundtrip(&agent.ssh_sock, &request);
    assert_eq!(response, vec![sshagent::SSH_AGENT_FAILURE]);
}

#[test]
fn a_garbled_message_does_not_kill_the_connection() {
    let key = SshKey::generate("laptop", "a@a").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));
    agent.unlock();

    let mut stream = UnixStream::connect(&agent.ssh_sock).unwrap();

    // A sign request whose string length runs past the end of the message.
    let mut garbage = vec![sshagent::SSH_AGENTC_SIGN_REQUEST];
    garbage.extend_from_slice(&999u32.to_be_bytes());
    garbage.extend_from_slice(b"short");
    sshagent::write_message(&mut stream, &garbage).unwrap();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let response = sshagent::read_message(&mut reader).unwrap().unwrap();
    assert_eq!(response, vec![sshagent::SSH_AGENT_FAILURE]);

    // The same connection still works for a well-formed request afterwards.
    sshagent::write_message(&mut stream, &[sshagent::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let response = sshagent::read_message(&mut reader).unwrap().unwrap();
    assert_eq!(response[0], sshagent::SSH_AGENT_IDENTITIES_ANSWER);
}

#[test]
fn control_socket_reports_status_and_serves_entries() {
    let key = SshKey::generate("laptop", "a@a").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));

    let locked = agent.client.status().unwrap();
    assert!(!locked.unlocked);
    assert_eq!(locked.ssh_keys, 0);

    // Nothing is served while locked, with an error that says what to do.
    let refused = agent.client.list_entries().unwrap_err().to_string();
    assert!(refused.contains("pass unlock"), "unhelpful error: {refused}");

    agent.unlock();

    let unlocked = agent.client.status().unwrap();
    assert!(unlocked.unlocked);
    assert_eq!(unlocked.ssh_keys, 1);
    assert_eq!(unlocked.vault.as_deref(), Some(agent.vault_path.as_path()));

    // Entries come back over the socket, SSH keys excluded from the listing.
    let entries = agent.client.list_entries().unwrap();
    assert_eq!(entries.len(), 1, "expected only the password entry, got {entries:?}");
    assert_eq!(entries[0].website, "GitHub");

    // ...and one entry with its secrets, resolved by name rather than id.
    let entry = agent.client.get_entry("github").unwrap();
    assert_eq!(entry.password, "the-github-password");
    assert_eq!(entry.username, "me@example.com");
    assert_eq!(
        entry.totp_code.as_ref().map(String::len),
        Some(6),
        "the agent did not compute a live TOTP code"
    );

    let keys = agent.client.list_ssh_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].fingerprint, key.fingerprint);

    // A query that matches nothing is an error, not an empty success.
    assert!(agent.client.get_entry("no-such-entry").is_err());
}

#[test]
fn shutdown_stops_the_agent_and_removes_its_sockets() {
    let agent = TestAgent::start(&[]);
    let ipc_path = agent.client.path().to_path_buf();
    let ssh_path = agent.ssh_sock.clone();

    agent.client.shutdown().unwrap();

    wait_until(|| !ipc_path.exists() && !ssh_path.exists(), "sockets were left behind");
    assert!(!agent.client.is_running());
}

#[test]
fn an_idle_session_locks_itself() {
    let key = SshKey::generate("laptop", "a@a").unwrap();
    let agent = TestAgent::start(std::slice::from_ref(&key));

    agent
        .client
        .unlock(&agent.vault_path, MASTER_PASSWORD, Some(Duration::from_secs(1)))
        .unwrap();
    assert!(agent.client.status().unwrap().unlocked);

    wait_until(
        || !agent.client.status().unwrap().unlocked,
        "the session never auto-locked",
    );

    let refused = agent.client.list_entries().unwrap_err().to_string();
    assert!(refused.contains("unlock"), "unhelpful error: {refused}");
}

#[test]
fn a_wrong_master_password_is_reported_not_accepted() {
    let agent = TestAgent::start(&[]);

    let error = agent
        .client
        .unlock(&agent.vault_path, "definitely-not-the-password", None)
        .unwrap_err()
        .to_string();

    assert!(error.to_lowercase().contains("password"), "unhelpful error: {error}");
    assert!(!agent.client.status().unwrap().unlocked);
}

/// Two agents must not fight over one socket.
#[test]
fn a_second_agent_refuses_to_take_over_a_live_socket() {
    let agent = TestAgent::start(&[]);

    let second = Agent::new(
        agent.client.path().to_path_buf(),
        agent.ssh_sock.with_extension("second"),
    );
    let error = second.run().unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
}

// --- small protocol helpers, kept local to the test ------------------------

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn read_string(buf: &[u8]) -> Option<&[u8]> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    buf.get(4..4 + len)
}

fn ssh_roundtrip(socket: &Path, request: &[u8]) -> Vec<u8> {
    let mut stream = UnixStream::connect(socket).expect("could not connect to the SSH agent socket");
    sshagent::write_message(&mut stream, request).unwrap();

    let mut reader = BufReader::new(stream);
    sshagent::read_message(&mut reader)
        .unwrap()
        .expect("agent closed the connection without replying")
}
