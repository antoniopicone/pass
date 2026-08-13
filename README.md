# Pass - Secure Password Manager

A cross-platform password manager built with Rust, featuring zero-knowledge encryption and a command-line interface.

## 🔐 Security Features

- **AES-256-GCM Encryption**: Military-grade authenticated encryption
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
- **💾 Portable Vault**: Single encrypted file, easy to backup and sync
- **🌍 Cross-Platform**: Works on macOS, Linux, and Windows
- **🔢 Built-in MFA codes**: Store TOTP secrets (scan the QR code or paste the URI) and generate 2FA codes alongside each entry

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

  Vault: passwords.vault
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

This creates a new encrypted vault file (`passwords.vault` by default) protected by your master password.

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
pass --vault /path/to/my-vault.vault list
```

## 🗄️ Vault File Format

The vault file uses a custom binary format:

```
┌─────────────────────────────────────┐
│ Magic Bytes (4 bytes): "PSVT"      │
├─────────────────────────────────────┤
│ Version (4 bytes): u32              │
├─────────────────────────────────────┤
│ Salt (32 bytes): Random             │
├─────────────────────────────────────┤
│ Nonce (12 bytes): Random            │
├─────────────────────────────────────┤
│ Encrypted Data (variable)           │
│ - JSON with password entries        │
│ - AES-256-GCM encrypted             │
├─────────────────────────────────────┤
│ Auth Tag (16 bytes): GCM tag        │
└─────────────────────────────────────┘
```

The encrypted JSON payload contains all password entries with metadata.

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
secret never leaves the vault. The TOTP secret is stored encrypted inside
the same vault entry and participates in merge/sync like any other field
(see below).

## 🔀 Merging vaults across devices

Every entry carries a `revision` counter (bumped on every edit or delete)
and a `deleted_at` tombstone instead of being removed outright. That makes
merging two independently-edited copies of a vault a simple, deterministic,
order-independent operation — no shared sync history required, and it
naturally supports deletions propagating like any other edit. See
`passlib/src/merge.rs` for the algorithm and its tests.

```bash
# Pull changes from another copy of the vault (e.g. synced via Nextcloud)
pass merge /path/to/synced/passwords.vault

# Or do it automatically: watch that copy and merge every time it changes
# (e.g. because the Nextcloud client just synced it down from another
# device), optionally publishing the merged result back to a shared path
# so other devices can pick it up too.
pass watch /path/to/synced/passwords.vault --publish /path/to/synced/passwords.vault
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

## 🏗️ Architecture

The project is organized as a Rust workspace with these packages:

- **`passlib`**: Core library with encryption, vault management, and the
  cross-device merge algorithm
- **`passcli`**: Command-line interface application
- **`passlib_ffi`**: C-compatible FFI bindings (used by native apps, e.g. `pass-apple`)
- **`pass-native-host`**: Native messaging host bridging the Chromium
  extension to `passlib`

### Library Structure

```
passlib/
├── src/
│   ├── lib.rs      # Public API
│   ├── crypto.rs   # Encryption primitives
│   ├── vault.rs    # Vault management
│   ├── entry.rs    # Password entry data structures
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
✅ Tampering detection (GCM authentication)  
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
- [ ] GUI application (Tauri)
- [ ] iOS/iPadOS support
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
- [ ] Direct Nextcloud WebDAV client (today `pass watch` expects a
      filesystem-synced copy, e.g. from the Nextcloud desktop client)

## ⚠️ Disclaimer

This software is provided as-is. While it uses industry-standard cryptographic algorithms, it has not undergone a professional security audit. Use at your own risk.

## 💬 Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Made with 🦀 Rust**
