# pass-howdy

"Unlock with your face" on Linux, via [howdy](https://github.com/boltgolt/howdy)
— the Linux counterpart to `pass-apple`'s Face ID/Touch ID
(`BiometricUnlock.swift`). Used by `passcli`, `pass-gnome`, and (through
`pass-native-host`) the Chromium extension.

## The trade-off, stated plainly

Howdy recognizes a face; it derives no key. So, exactly like Face ID/Touch
ID on Apple platforms, this crate doesn't make the vault's encryption
itself biometric — it stores the actual master password in the OS keyring
(secret-service — GNOME Keyring/KWallet, via the [`keyring`](https://crates.io/crates/keyring)
crate) once you opt in, and a successful howdy face match is what gates
*retrieving* that stored password, not the vault's encryption directly.

That means the master password exists at rest in the keyring, protected by
whatever the keyring itself provides — a real, deliberate departure from
"master password never stored anywhere" for anyone who opts in. If you
don't enable face unlock for a vault, nothing changes: the master password
prompt works exactly as it always did.

## The isolated PAM service

Authentication runs against a dedicated PAM service, `pass-howdy`
(`/etc/pam.d/pass-howdy`, installed by [`setup-pam-service.sh`](setup-pam-service.sh) —
also reachable via the repo's top-level `install.sh --with-howdy`).
Deliberately its own service file rather than piggybacking on
`sudo`/`login`:

```
auth sufficient <path-to-pam_howdy.so, filled in at install time>
auth required   pam_deny.so
account required pam_permit.so
```

`sufficient` + `pam_deny.so`: a successful face match immediately succeeds
the whole stack; anything else (no match, no camera, howdy misconfigured)
always denies. There is deliberately no fallback to a system password
prompt inside this stack — [`unlock_with_face`] uses PAM's "null"
conversation handler specifically so an unexpected prompt from a
misconfigured module fails loudly instead of silently asking for something
on our behalf. `pass`'s own master-password prompt is the fallback, one
layer up, in the caller.

This service is never referenced by `sudo`, `login`, or anything else on
the system, and installing it never edits an existing PAM file — only
`setup-pam-service.sh`'s own new one.

## Setup

```bash
# 1. Install howdy itself first, if you haven't: https://github.com/boltgolt/howdy
# 2. Enroll your face with it: sudo howdy add
# 3. Install the isolated PAM service (needs sudo — see above):
./setup-pam-service.sh
```

From there, `passcli`/`pass-gnome`/the Chromium extension each offer to
enable face unlock the next time you unlock a vault manually — see their
own docs. Nothing needs enabling per-app beyond that; enabling it for a
vault from any one client makes it available in every other client too,
since they all share the same keyring entry (keyed by the vault's file
path) and the same PAM service.

## Build requirement: libclang

This crate depends on [`pam-client`](https://crates.io/crates/pam-client),
whose `build.rs` uses `bindgen` to generate PAM's FFI bindings at compile
time, which needs `libclang`. On Debian/Ubuntu, install `libclang-dev`, or
let the repo's top-level `install.sh` auto-detect an already-installed
`libclang-*.so` and point `bindgen` at it via a local (non-system) symlink
shim if the `-dev` package isn't installed.

## API

- `is_installed()` / `is_configured()`: whether howdy itself, and this
  crate's PAM service respectively, look set up on this machine.
- `is_available_for(vault_path)`: whether "unlock with your face" can be
  *offered* for this exact vault right now (installed + configured +
  already enrolled).
- `can_enroll()`: whether enrollment could be offered at all, independent
  of whether a given vault has opted in yet.
- `store_password` / `has_stored_password` / `forget_password`: manage the
  keyring entry for a vault.
- `unlock_with_face(vault_path)`: authenticate via howdy, then return the
  stored master password on success.
