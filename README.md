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
```

This is the building block for keeping the vault in sync across devices
sharing a Nextcloud (or any file-sync) folder: point `merge` at the synced
copy whenever it changes, then let the sync client push the merged result
back out.

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
- [ ] TOTP 2FA support
- [ ] Secure password sharing
- [x] Browser extension (Chromium, local vault + merge — see `chrome-extension/`)
- [ ] Direct Nextcloud (WebDAV) sync + file-watcher auto-merge

## ⚠️ Disclaimer

This software is provided as-is. While it uses industry-standard cryptographic algorithms, it has not undergone a professional security audit. Use at your own risk.

## 💬 Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Made with 🦀 Rust**
