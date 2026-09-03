# Security model

This document says what `pass` protects, what it does not, and why. It is
deliberately specific: a password manager that is vague about its limits is
asking to be trusted for things it cannot do.

**`pass` has not had a professional security audit.**

## 1. At rest — the vault file

The vault is a standard KDBX4 database, the format KeePass/KeePassXC use, via
the [`keepass`](https://crates.io/crates/keepass) crate:

- **AES-256** outer encryption with **HMAC-SHA256** block authentication, so
  tampering is detected rather than silently decrypted into garbage.
- **Argon2id** key derivation at 64 MiB / 10 iterations / 4 lanes. These are
  set explicitly (`strengthen_kdf` in `passlib/src/vault.rs`) rather than
  inherited from the crate's defaults, which are deliberately cheap for test
  runs and would be irresponsible on a real vault.
- **ChaCha20** inner stream cipher over protected fields (passwords, SSH
  private keys, the sharing identity), so those are not in the clear even
  within the decrypted XML.

Because it is a real KDBX4 file, its at-rest security is the same as
KeePassXC's, and is reviewable by anyone who knows that format.

## 2. In memory — while unlocked

Secrets that survive between operations (`passlib::secmem`):

| Layer | What it stops |
|---|---|
| `zeroize` on drop | The secret lingering in freed heap memory |
| `mlock` (via `memsec`) | The page being written to swap or a hibernation image |
| `MADV_DONTDUMP` on Linux | The secret appearing in a core dump |
| `Shielded` — XChaCha20-Poly1305 under a per-process key | A memory dump taken while the process is idle containing plaintext |

The agent (`pass-agent`) holds **no decrypted vault between requests**. It
keeps only the master password and the SSH keys, each shielded; everything
else is read by reopening the vault for that one request and dropping it.

`mlock` can legitimately fail on a system with a low `RLIMIT_MEMLOCK`. That is
not fatal and not silent: `SecretBuf::is_locked` reports it.

### What this does not stop

An attacker who can read this process's memory **while it is running** — same
uid, or root, or a debugger — defeats all of it: they can read the shield key
too, and can `ptrace` the moment of decryption. These primitives raise the cost
of the *offline* attacks they are designed for (swap file, hibernation image,
core dump, cold boot). They are not a defence against a compromised account.

## 3. The agent's sockets

Two Unix sockets, both `0600` inside a `0700` directory, preferring
`$XDG_RUNTIME_DIR` (per-user, already `0700`, cleared at logout):

- the control socket, over which secrets do travel;
- the SSH agent socket, over which signatures — never keys — travel.

This is OpenSSH's own model for `ssh-agent`. Anyone able to bypass those
permissions could read the agent's memory anyway, so no additional handshake
would add security.

**The SSH agent is read-only.** `ssh-add` cannot add, remove, or overwrite
keys. A key that reached the agent without being in the vault would be a
private key living somewhere the user cannot see, back up, or sync — the exact
situation storing keys in the vault removes.

The agent never returns the master password over the socket, only derived
results. A client that needs to *write* to the vault prompts for it.

## 4. Quick unlock (PIN)

`pass quick-unlock` seals the master password with XChaCha20-Poly1305 under an
Argon2id key derived from a PIN (128 MiB / 12 iterations — deliberately higher
than the vault's own KDF, because a PIN has far less entropy to protect), and
writes it to a `0600` file bound to the vault path as associated data.

Two different attacks, two different defences:

- **Guessing at your keyboard** — counted in the record; after 5 failures the
  record is destroyed and the master password is the only way back.
- **Guessing offline, from a copy of the file** — no counter helps; only the
  Argon2id cost does. This is why a minimum PIN length is enforced and a
  digits-only PIN produces an explicit warning: 6 digits is 10⁶ candidates, and
  Argon2id slows that down without making it safe.

`--verify-command` (e.g. `fprintd-verify`) is a **second factor before** the
PIN, not a replacement for it. A fingerprint cannot derive a key. Replacing the
PIN outright would mean storing the master password somewhere the OS hands back
after a biometric check, which on Linux means trusting the login keyring rather
than hardware — strictly weaker, so `pass` does not offer it.

## 5. Sharing

`pass share` seals entries to a recipient's X25519 public key, mixing two
Diffie-Hellman exchanges: an ephemeral one (so compromising the sender's
identity key later does not decrypt bundles already sent) and a static
sender↔recipient one (so the recipient learns *who* sent it, rather than
accepting an anonymous bundle from anyone who knows their public key). The
bundle header is authenticated as associated data.

**There is no revocation, and there cannot be.** Once someone has seen a
password, taking it back means changing the password, not deleting a file.

## 6. Peer-to-peer sync

`pass sync` replicates a vault directly between your devices. Two secrets do
two different jobs, and keeping them apart is the whole design:

| secret | answers | shared with |
|---|---|---|
| device key (Ed25519) | *who wrote this change* | nobody — one per device |
| sync key (32 bytes) | *what does it say* | every device holding this vault |

So a change travels as ciphertext (XChaCha20-Poly1305, entry id bound in as
associated data) signed by a named device. Both keys live in the vault, which
means a new device gets them the way it gets everything else — by holding the
file — and nothing has to be exchanged over the network to bootstrap.

**A device may write into your vault only after you pair it** with
`pass sync trust`. There is no trust on first contact: a machine that reaches
the port and is not on the roster is refused, and you are told once so you can
pair it if it is yours.

**The transport is plain HTTP**, on a port bound to your tailnet address (or
loopback when there is no tailnet), never to every interface. That is
deliberate, not an omission: confidentiality and authenticity are properties
of each change, not of the connection, which is what makes it safe to let an
always-on machine you do not fully trust relay for devices that are never
awake at the same time.

### What a peer on that port can and cannot do

It **cannot** read a password, forge a change, or influence how the merge
resolves. It **can**:

- learn the UUIDs of entries that changed, which device changed them, and
  when — the metadata around each change is in the clear, because the merge
  needs it;
- read your op-log if it asks: requests themselves are not authenticated, so
  anything that can reach the port sees that metadata, paired or not;
- withhold changes, which the next round with any other peer repairs.

If that metadata matters to you, do not expose the port beyond a network you
trust — which is why the default binding is what it is.

**`pass sync forget` is not revocation.** It stops a device writing into your
vault from then on. It takes back nothing it has already read. As with
sharing, the real answer to a lost device is to change the passwords.

## 7. What `pass` does not protect against

- **Keyloggers**, including anything reading your X11 or `uinput` input.
- **A compromised account**: anything running as you can read the agent's
  memory, the vault file, and the quick-unlock record.
- **Root, or physical access to an unlocked machine.**
- **Shoulder surfing**, and `pass type` typing into whatever window has focus
  if focus moves mid-sequence.
- **`pass run`'s environment variables**: on Linux any process running as you
  can read `/proc/<pid>/environ`. It keeps secrets out of *files* and shell
  history, which is where they actually leak from — it is not a boundary
  against your own account.
- **A lost or forgotten master password**: there is no recovery, by design.
- **Traffic analysis of a synced vault**: a file-sync provider cannot read the
  vault, but learns when you change it. The same is true of anything that can
  reach `pass sync`'s port — see §6.

## 8. Reporting a problem

Open an issue at <https://github.com/antoniopicone/pass>. For something you
believe is exploitable, please say so in the title rather than posting a
working exploit as the first message.
