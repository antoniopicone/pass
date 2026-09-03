# Pass - Secure Password Manager

A cross-platform password manager built with Rust, featuring zero-knowledge
encryption and a command-line interface. The vault is a real **KDBX4**
file — the native format used by [KeePass](https://keepass.info)/[KeePassXC](https://keepassxc.org)
— so it opens directly in KeePassXC (and vice versa: a database created in
KeePassXC opens directly in `pass`). `pass` isn't a KeePassXC plugin or
fork; it's an independent, interoperable client for the same file format,
verified in both directions against the real `keepassxc-cli`/KeePassXC
binary (see "KDBX4 / KeePassXC compatibility" below).

## 🔐 Security Features

- **KDBX4 format**: AES-256 outer encryption with HMAC-SHA256 block
  authentication, ChaCha20 for protected in-memory fields — the same
  construction KeePassXC itself uses
- **Argon2id Key Derivation**: Memory-hard, GPU-resistant key derivation function
- **Zero-Knowledge Architecture**: Master password never stored anywhere
- **No Password Recovery**: If you forget your master password, your data cannot be recovered
- **Memory Safety**: Automatic secure memory wiping using Rust's `zeroize`

## ✨ Features

- **🎨 Interactive Mode**: User-friendly menu-driven interface for easy password management
- **⚡ Session Management**: Unlock once, perform multiple operations without re-authentication
- **🔍 Powerful Search**: Find passwords by website name, username, or URL
- **📋 Clean Interface**: Colorized output with intuitive navigation
- **🔐 Traditional CLI**: Full command-line support for scripting and automation
- **💾 KeePassXC-compatible vault**: Single `.kdbx` file, openable directly in KeePassXC, easy to backup and sync
- **🌍 Cross-Platform**: Works on macOS, Linux, and Windows
- **🔢 Built-in MFA codes**: Store TOTP secrets (scan the QR code or paste the URI) and generate 2FA codes alongside each entry, using the same `otp` field convention as KeePassXC
- **🔑 SSH agent**: keep SSH keys in the vault instead of `~/.ssh`, served over a real OpenSSH agent socket (see below)
- **🧠 Background agent**: unlock once, auto-lock on idle, with the master password held encrypted in RAM and locked out of swap
- **⌨️ Autotype**: type credentials into any window, for apps with no integration at all
- **📦 Env injection**: `pass run` puts a secret in one command's environment instead of a `.env` file
- **🔗 Peer-to-peer sync**: replicate a vault directly between your own devices — no server, no file-sync service, encrypted and signed end to end
- **🤝 Serverless sharing**: hand someone an entry as a sealed, armored block over any channel
- **🎲 Password generator**: character passwords and diceware-style passphrases

## 🚀 Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/antoniopicone/pass.git
cd pass

# Build the release binary
cargo build --release

# The binary will be at: ./target/release/pass

# Optional: Install to system
cargo install --path passcli
```

## 📖 Usage

### Interactive Mode (Recommended)

The easiest way to manage your passwords is using the interactive menu:

```bash
pass interactive
```

This provides a user-friendly menu-driven interface where you can:
- **Unlock once** - Enter your master password only at the start
- **Browse passwords** - See all your passwords in a clean list
- **Search** - Quickly find passwords by website, username, or URL
- **Add/Edit/Delete** - Full CRUD operations with guided prompts
- **View passwords** - Show specific passwords on demand

**Example Session:**
```bash
$ pass interactive
Master password: ********

╔════════════════════════════════════════╗
║   Password Manager - Interactive Mode  ║
╚════════════════════════════════════════╝

  Vault: passwords.kdbx
  Status: Unlocked (3 entries)

────────────────────────────────────────────────────────────

What would you like to do?

> 📋 List all passwords
  🔍 Search passwords
  ➕ Add new password
  ✏️  Edit password
  🗑️  Delete password
  🔑 View specific password
  🚪 Exit
```

---

### Command-Line Mode

For scripting or single operations, use the traditional CLI commands:

### Initialize a New Vault

```bash
pass init
```

This creates a new encrypted KDBX4 vault file (`passwords.kdbx` by default) protected by your master password.

### Add a Password Entry

```bash
pass add
```

Interactive prompts will ask for:
- Website name
- URL
- Username/Email
- Password

### List All Entries

```bash
pass list
```

Shows all password entries without displaying the actual passwords.

### Get a Specific Entry

```bash
# By ID
pass get abc123-def456-...

# By website name (case-insensitive search)
pass get github
```

### Update an Entry

```bash
pass update <entry-id>
```

### Delete an Entry

```bash
pass delete <entry-id>
```

### Custom Vault Location

```bash
# Use a different vault file
pass --vault /path/to/my-vault.kdbx list
```

## 🗄️ KDBX4 / KeePassXC compatibility

The vault is a standard KDBX4 database (via the [`keepass`](https://crates.io/crates/keepass)
Rust crate), not a custom format. Concretely, a [`PasswordEntry`](passlib/src/entry.rs) maps to:

| `pass` field | KDBX4 entry field |
|---|---|
| website | `Title` |
| url | `URL` |
| username | `UserName` |
| password | `Password` (protected) |
| MFA/TOTP secret | `otp` (an `otpauth://` URI — the same field KeePassXC itself writes) |
| deletion | moved into a `Recycle Bin` group, KeePassXC's own soft-delete convention |

This was verified against the real `keepassxc-cli` (KeePassXC 2.7), not
just our own code, in both directions:
- a vault created and populated entirely by `pass` (including an MFA
  secret) opens in `keepassxc-cli`, lists correctly, and produces the
  **exact same live TOTP code** as `pass totp show`
- a database created entirely by `keepassxc-cli db-create`/`add` opens
  and reads correctly in `pass`, password included

Since it's a real KDBX4 file, anything that speaks the format works too —
back it up, inspect it, or open it in the KeePassXC GUI/mobile apps
whenever you want, independent of `pass` entirely.

## 🔢 MFA / TOTP codes

Attach a service's 2FA secret to an entry by scanning the QR code it shows
you during MFA setup (or by pasting the `otpauth://` URI directly), and
`pass` will generate the current 6-digit code on demand — no separate
authenticator app needed.

```bash
# Scan a QR code you saved as an image (PNG/JPEG/GIF/BMP/WebP)
pass totp add <entry-id> --qr ~/Downloads/github-2fa-qrcode.png

# Or paste the otpauth:// URI directly (e.g. from a "can't scan?" link)
pass totp add <entry-id> --uri "otpauth://totp/GitHub:me@example.com?secret=...&issuer=GitHub"

# Show the current code (also shown automatically by `pass get` and interactive view)
pass totp show <entry-id-or-website>

pass totp remove <entry-id>
```

Codes are generated locally with the standard TOTP algorithm (RFC 6238,
HMAC-SHA1/256/512), validated against the official RFC test vectors — the
secret never leaves the vault. The secret is stored in the entry's `otp`
field (an `otpauth://` URI) using the exact convention KeePassXC uses, so
a code set up in `pass` shows up correctly in KeePassXC's own TOTP button
and vice versa.

## 🔀 Merging vaults across devices

Cross-device sync is just [`keepass::Database::merge`](https://docs.rs/keepass) —
the same database-merge logic KeePassXC itself ships — reconciling two
independently-edited copies of the vault using each entry's KDBX
last-modification timestamp, with deletions propagating via the Recycle
Bin group rather than a custom tombstone scheme. No proprietary merge
format, no shared sync history required.

```bash
# Pull changes from another copy of the vault (e.g. synced via Nextcloud)
pass merge /path/to/synced/passwords.kdbx

# Or do it automatically: watch that copy and merge every time it changes
# (e.g. because the Nextcloud client just synced it down from another
# device), optionally publishing the merged result back to a shared path
# so other devices can pick it up too.
pass watch /path/to/synced/passwords.kdbx --publish /path/to/synced/passwords.kdbx
```

`pass watch` uses native filesystem events (inotify/FSEvents/ReadDirectoryChangesW
via the `notify` crate), debounces the burst of events a single atomic save
produces, and re-merges automatically — this is the piece that turns the
manual `pass merge` step into always-on sync across devices sharing a
Nextcloud (or any file-sync) folder.

## 🔗 Peer-to-peer sync (no server, no file-sync service)

`pass merge`/`pass watch` above put the encrypted file through somebody
else's machine and need that service to be working. `pass sync` is the other
transport: devices that can reach each other reconcile **directly**, with no
server and nothing else running.

```bash
# Set up the second device by copying the vault file across once — that is
# what carries the key its devices seal changes with, so there is no key
# exchange to get wrong.
scp laptop:~/passwords.kdbx ~/passwords.kdbx

# On each device, run an agent that also syncs
pass agent run --sync

# Read this device's key, and tell the other device to accept it
pass sync id
pass sync trust laptop 'pass-device-pk1:…'   # on the other device, and vice versa

pass sync status     # what it is doing, who it knows, and the merge fingerprint
pass sync now        # reconcile immediately instead of at the next round
pass sync devices    # who is allowed to write into this vault
pass sync forget bob # stop accepting a device's changes
```

**How it works.** Each entry you change becomes one op in an append-only
log, sealed with a key that exists only inside the vault and signed by this
device. Peers exchange version vectors (*"here is what I have seen, send me
the rest"*) and merge the ops with an HLC last-writer-wins rule; the op that
wins is written back into the KDBX vault, where the replaced password stays
recoverable from the KDBX history. The flows are drawn out in
[docs/SYNC_FLOWS.md](docs/SYNC_FLOWS.md); the reasoning behind them is in
[docs/SYNC_STRATEGY.md](docs/SYNC_STRATEGY.md), and the code in
[`passlib::sync`](passlib/src/sync/).

**What it is not.** It is not trust-on-first-contact: a device may write into
your vault only after you have paired it by hand, because "it reached the
port, so it must be yours" is not a decision a password manager should make
for you. And a peer that is *not* paired cannot read what it relays (payloads
are sealed) or influence the merge, which is what makes it safe to let an
always-on machine act as a relay for devices that are never awake at the same
time. It *can* see which entry ids changed and when — the metadata is in the
clear, because the merge needs it. See
[SECURITY.md §6](SECURITY.md) for exactly what is and is not protected.

**Where it looks for devices.** A bootstrap address you give it
(`--sync-peer host:port`), the tailnet if Tailscale is running, and — the one
that matters — peer exchange: after a single contact with any peer, a device
knows the whole mesh and keeps knowing it. The port is bound to your tailnet
address, or to loopback if there is no tailnet; it is deliberately *not*
opened on every interface.

Two devices have converged when `pass sync status` prints the same
`Fingerprint` on both. If it differs, the problem is the merge, not the
network.

## 🌐 Chromium extension

`chrome-extension/` contains a Manifest V3 extension that unlocks the vault,
searches/copies/autofills entries, and can trigger the same merge from its
popup. It talks to the vault through a small native messaging host
(`pass-native-host`) rather than over the network. See
`chrome-extension/README.md` for setup.

## 🐧 GNOME app

`pass-gnome` is a native GTK4/libadwaita desktop app (Rust, using `passlib`
directly — no FFI hop needed since both are Rust). It covers the same core
flows as the CLI: unlock/create a vault, search entries, reveal/copy
password and MFA code with a live countdown, add/edit/delete, attach an MFA
secret by pasting an `otpauth://` URI or picking a QR code image, and merge
in another vault copy from the header menu.

```bash
cargo run --release -p pass-gnome
```

Requires GTK4 ≥ 4.12 and libadwaita ≥ 1.5 development packages installed
(e.g. `libgtk-4-dev libadwaita-1-dev` on Debian/Ubuntu) to build.

## 🍎 macOS / iOS

`pass-apple/` has a shared SwiftUI app (unlock/create, search, view/reveal/
copy password and MFA code with a live countdown, add/edit/delete, attach
MFA via `otpauth://` URI or a QR photo scanned with Vision, merge another
vault copy) for both platforms, backed by `passlib_ffi`.

**Unlike every other client in this repo, this one is unverified.** It was
written in a Linux sandbox with no Xcode, no macOS/iOS SDK, and no way to
install even the Linux Swift toolchain to compile-check it (outbound
network policy blocks `download.swift.org`) — so nothing in `pass-apple/`
has been built or run. See `pass-apple/README.md` for exactly what that
means, and the setup steps (`build-xcframework.sh`, then a few minutes in
Xcode) to build and fix it on a real Mac.

## 🧠 The agent

Most of the features below need one thing the CLI alone cannot provide: a
vault that is already unlocked. `pass-agent` is that — a background process
holding the session, with two Unix sockets.

```bash
pass agent run                 # foreground; see dist/systemd/ for a user service
pass unlock                    # hand it the master password, once
pass status                    # what is it holding, and for how much longer
pass lock                      # wipe the session now
```

It holds **no decrypted vault between requests**: only the master password and
the SSH keys, each encrypted in RAM (XChaCha20-Poly1305 under a per-process
key) and `mlock`ed out of swap. Everything else is read by reopening the vault
for that one request. The session auto-locks after an idle timeout.

See [SECURITY.md](SECURITY.md) for the full model.

## 🔑 SSH keys and the SSH agent

`~/.ssh/id_ed25519` is a plaintext private key on disk, readable by anything
running as you. In the vault it is encrypted with everything else, syncs with
everything else, and is only ever exposed through the agent — which hands out
*signatures*, never the key.

```bash
pass ssh generate laptop                  # a fresh Ed25519 key, straight into the vault
pass ssh import ~/.ssh/id_ed25519         # or move an existing one in
pass ssh list
pass ssh pub laptop >> ~/authorized_keys  # the public half

export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/pass/ssh-agent.sock"
ssh-add -l                                # OpenSSH sees the vault's keys
git push                                  # signs from the vault
```

Keys are stored **the way KeePassXC stores them**: the private key as an entry
attachment described by a `KeeAgent.settings` field. A key added by `pass`
appears in KeePassXC's SSH Agent tab, and vice versa.

The agent is deliberately **read-only** — `ssh-add` cannot add, remove or wipe
keys, because a key that got in that way would live somewhere you cannot back
up or sync.

## 📦 Injecting secrets into a command

```bash
pass run --secret STRIPE_KEY=stripe --secret GH_USER=github:username -- ./deploy.sh
```

Fields are `password` (default), `username`, `totp`, `notes`. The child's exit
code is propagated, so this is transparent in a script. Note this keeps secrets
out of *files* and shell history — it is not a boundary against your own
account (see [SECURITY.md](SECURITY.md)).

## ⌨️ Autotype

For the applications with no password-manager integration at all — a VPN
client, a VM console, a game launcher:

```bash
pass type github                    # username, Tab, password
pass type github --with-totp        # ...then Tab and the current MFA code
pass type github --password-only --submit
pass type github --dry-run          # what it would type, secrets redacted
```

It drives the tool your desktop already ships (`wtype`/`ydotool` on Wayland,
`xdotool` on X11, AppleScript on macOS) rather than linking an input library,
so a machine without those can still build and use everything else.

## 🔓 Quick unlock (PIN, and optionally a fingerprint)

A master password strong enough to protect a vault is too long to retype every
time the agent auto-locks — so people disable auto-lock, or weaken the master
password. Both are worse than this:

```bash
pass quick-unlock enable
pass unlock --pin

# with a fingerprint reader as a second factor before the PIN
pass quick-unlock enable --verify-command fprintd-verify
```

The master password is sealed under an Argon2id key derived from the PIN. Five
wrong PINs destroy the record. The `--verify-command` is a second factor
*before* the PIN, not a replacement — a fingerprint cannot derive a key, and
the alternative would mean trusting the login keyring instead of hardware.

## 🤝 Sharing an entry with someone, with no server

Bitwarden shares through an organisation its server owns. With no server there
is nothing to own a collection — so a share here is a *file*, sealed to one
recipient, sent over whatever channel you already trust.

```bash
pass share init                                    # your identity; prints a public key
pass share add marta pass-share-pk1:AbC...         # remember hers
pass share export netflix --to marta > netflix.pass
pass share import netflix.pass                     # on her side
```

X25519 with two Diffie-Hellman exchanges: an ephemeral one for forward secrecy,
and a static sender↔recipient one so the recipient learns *who* shared with
them rather than accepting an anonymous bundle from anyone who knows their
public key.

**There is no revocation, and there cannot be**: once someone has a password,
taking it back means changing it. See
[docs/SYNC_STRATEGY.md](docs/SYNC_STRATEGY.md).

## 🎲 Password generator

```bash
pass gen                          # 20 chars, all sets, ambiguous characters excluded
pass gen --passphrase --length 6  # diceware-style, for secrets you have to retype
pass add --website GitHub --username me --generate
```

## 🏗️ Architecture

The project is organized as a Rust workspace with these packages:

- **`passlib`**: Core library — KDBX4 vault storage (via the `keepass`
  crate), cross-device merge, and TOTP/MFA code generation
- **`passcli`**: Command-line interface application
- **`passlib_ffi`**: C-compatible FFI bindings — init/unlock/CRUD, merge,
  and MFA/TOTP — used by `pass-apple`'s Swift wrapper
- **`pass-native-host`**: Native messaging host bridging the Chromium
  extension to `passlib`
- **`pass-gnome`**: Native GTK4/libadwaita desktop app for Linux
- **`pass-apple`**: Shared SwiftUI app for macOS/iOS (unverified — see above)
- **`pass-agent`**: Background agent holding the unlocked session, plus an
  OpenSSH-compatible agent serving the vault's SSH keys (Unix only)

### Library Structure

```
passlib/
├── src/
│   ├── lib.rs      # Public API
│   ├── vault.rs    # KDBX4 vault storage, CRUD, merge (via the `keepass` crate)
│   ├── entry.rs    # Password entry data structures
│   ├── totp.rs     # RFC 6238 TOTP + otpauth:// URI (de)serialization
│   ├── secmem.rs   # mlock + zeroize + in-RAM encryption of live secrets
│   ├── sshkey.rs   # SSH keys, stored in KeePassXC's own KeeAgent format
│   ├── share.rs    # Serverless sharing: X25519-sealed entry bundles
│   ├── generator.rs# Password and passphrase generation
│   └── error.rs    # Error types
└── Cargo.toml
```

## 🧪 Running Tests

```bash
# Test the core library
cd passlib
cargo test

# Test with output
cargo test -- --nocapture
```

## 📋 Requirements

- **Rust**: 1.70 or later
- **Supported Platforms**: 
  - macOS (Intel & Apple Silicon)
  - Linux (x86_64, ARM64)
  - Windows (planned)

## 🔒 Security Considerations

### What This Protects Against

✅ Data at rest encryption  
✅ Brute-force attacks (Argon2id is memory-hard)  
✅ Tampering detection (KDBX4's HMAC-SHA256 block authentication)  
✅ GPU-based attacks (Argon2id resistant)  

### What This Does NOT Protect Against

❌ Keyloggers on your system  
❌ Memory dumps while vault is unlocked  
❌ Compromised system with root/admin access  
❌ Shoulder surfing  

See [SECURITY.md](SECURITY.md) for the detailed model — what the memory
hardening does and doesn't do, how the agent's sockets are protected, and the
exact limits of quick unlock and sharing.

**Best Practices:**
- Use a strong, unique master password (12+ characters, mixed case, numbers, symbols)
- Keep your vault file backed up (it's just a file!)
- Don't run on untrusted systems
- Lock your screen when away

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🛣️ Roadmap

- [x] Core encryption library
- [x] CLI application 
- [x] GUI application (GNOME/GTK4 — see `pass-gnome/`; a Tauri app was the
      original idea but a native GTK4/libadwaita app fit better on Linux)
- [~] macOS app (SwiftUI) — see `pass-apple/`; written but **unverified**,
      needs a real Mac for its first build (no Xcode/macOS SDK in this
      environment — see `pass-apple/README.md`)
- [~] iOS support — same shared SwiftUI source as the macOS app, same
      caveat
- [x] Password generator (`pass gen`, characters or passphrase)
- [ ] Clipboard integration with auto-clear
- [x] TOTP 2FA support (`pass totp`, QR code or URI — see above)
- [x] Secure password sharing (`pass share`, X25519-sealed bundles, no server)
- [x] Background agent with auto-lock (`pass agent`)
- [x] SSH agent serving keys from the vault (`pass ssh`, KeePassXC-compatible storage)
- [x] Autotype into any window (`pass type`)
- [x] Secret injection into a command's environment (`pass run`)
- [x] Quick unlock with a PIN, optional biometric second factor (`pass quick-unlock`)
- [ ] KDBX4 keyfile support (see docs/SYNC_STRATEGY.md §7)
- [ ] Direct LAN peer-to-peer sync (see docs/SYNC_STRATEGY.md §3.2)
- [ ] Passkey (WebAuthn/FIDO2) support — storing passkey metadata for
      record-keeping is feasible; acting as a real authenticator the
      browser invokes during login needs OS-level CTAP2 integration and is
      a materially bigger project than the rest of this roadmap
- [x] Browser extension (Chromium, local vault + merge — see `chrome-extension/`)
- [x] File-watcher auto-merge (`pass watch`, see above)
- [x] KDBX4 / KeePassXC-compatible vault format (verified against real
      `keepassxc-cli` in both directions — see above)
- [ ] Direct Nextcloud WebDAV client (today `pass watch` expects a
      filesystem-synced copy, e.g. from the Nextcloud desktop client)

## ⚠️ Disclaimer

This software is provided as-is. While it uses industry-standard cryptographic algorithms, it has not undergone a professional security audit. Use at your own risk.

## 💬 Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Made with 🦀 Rust**
