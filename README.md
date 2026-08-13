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

### Library Structure

```
passlib/
├── src/
│   ├── lib.rs      # Public API
│   ├── vault.rs    # KDBX4 vault storage, CRUD, merge (via the `keepass` crate)
│   ├── entry.rs    # Password entry data structures
│   ├── totp.rs     # RFC 6238 TOTP + otpauth:// URI (de)serialization
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
- [ ] Password generator
- [ ] Clipboard integration with auto-clear
- [x] TOTP 2FA support (`pass totp`, QR code or URI — see above)
- [ ] Secure password sharing
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
