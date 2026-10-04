# Pass — macOS / iOS clients

A shared SwiftUI app (unlock/create vault, search, view/reveal/copy
password and MFA code with a live countdown, add/edit/delete, attach MFA
via `otpauth://` URI or a QR code photo, import another vault file,
import from Apple Passwords' CSV export), plus an **AutoFill credential
provider extension** so Pass can replace Apple Passwords for filling
logins and verification codes system-wide — all backed
by `passlib_ffi` — the same Rust core `pass`, `pass-gnome`, and the
Chromium extension use, opening the same real KDBX4/KeePassXC-compatible
`.kdbx` files. Every mutation pushes to the local
[`pass-syncd`](../pass-syncd/) daemon automatically, and a background timer
pulls other devices' changes in every few seconds while unlocked — see the
top-level README's "Cross-device sync" section.

## ⚠️ Verification status — please read before opening this in Xcode

Every other client in this repo (the CLI, the GNOME app, the Chromium
extension) was actually built and exercised in this environment — real
binaries, real `cargo test`, a real GTK4 GUI driven end-to-end under Xvfb,
real interop verified against a genuine `keepassxc-cli`. **This one is
different.** This session runs in a Linux sandbox with no Xcode, no macOS
or iOS SDK, and no simulator — and the one path that could have gotten
partial verification (installing the Linux Swift toolchain to at least
compile-check the non-UI `PassKit` package) is blocked by this
environment's outbound network policy (`download.swift.org` is denied).

So: **nothing in `Package.swift`, `Sources/PassKit/`, or `App/` has been
compiled, let alone run.** It was written carefully — every `passlib_ffi.h`
call site was cross-checked against the header by hand, pointer ownership
follows the documented `*_free` contract, platform minimums were picked to
match the SwiftUI APIs actually used — but "carefully written by hand" is
not the same guarantee as "the compiler and a simulator agree it works."
Treat the first build on a real Mac as the first real test of this code,
and expect to fix at least small things (a typo, an API shape that drifted
between Swift versions, an Xcode project setting) before it runs.

## What's here

```
pass-apple/
├── Package.swift              SPM package: PassKitFFI (binary) + PassKit (Swift wrapper)
├── build-xcframework.sh       Run on macOS: builds passlib_ffi for all Apple targets → PassKitFFI.xcframework
├── build-macos-app.sh         Run on macOS: builds a runnable .build/Pass.app without an Xcode project
├── Sources/PassKit/           Swift wrapper around passlib_ffi.h (Vault, PasswordEntry, errors)
├── Config/                    xcconfigs: App Group + keychain group derived from DEVELOPMENT_TEAM
├── Pass/                      The app target (macOS + iOS)
│   ├── Pass.entitlements      Keychain group, App Group, AutoFill provider
│   ├── Info.plist             Adds the App Group/keychain group names (merged with Xcode's)
│   └── App/                   SwiftUI source: PassApp, RootView, AppState, Clipboard, Views/
├── AutoFill/                  The AutoFill credential provider extension (one target per platform)
│   ├── CredentialProviderViewController.swift  What the system calls
│   ├── AutoFillModel.swift / AutoFillView.swift  Unlock + pick a login or verification code
│   ├── Info.plist             NSExtension: ProvidesPasswords, ProvidesOneTimeCodes
│   └── AutoFill-{macOS,iOS}.entitlements
├── Shared/                    Compiled into the app AND the extension
│   ├── SharedConfig.swift     App Group container, shared defaults, vault path
│   ├── BiometricUnlock.swift  Face ID/Touch ID master password, in the shared keychain group
│   ├── CredentialIdentities.swift  Feeds the system's AutoFill suggestions (no secrets)
│   └── SiteMatcher.swift      Entry ⇄ website host matching
└── Scripts/bundle-helpers.sh  macOS build phase: CLI + Chromium native host into Pass.app, team-signed
```

## Quick macOS build (no Xcode project)

```bash
cd pass-apple
./build-macos-app.sh          # CONFIGURATION=debug / ARCH=x86_64 to override
open .build/Pass.app
```

This compiles `passlib_ffi`, `PassKit` and `App/` directly with
`cargo`/`swiftc` and assembles an ad-hoc signed `Pass.app` (menu bar icon
included). It needs Xcode with its license accepted, but not the
xcframework or an `.xcodeproj`. It's signed without `Pass.entitlements`,
because `keychain-access-groups` needs a real team ID, so Touch ID unlock
may not be able to store the password in this build. Use the Xcode setup
below for a properly signed app, and for iOS.

## Setup (on a Mac)

1. **Build the Rust core for Apple platforms:**

   ```bash
   cd pass-apple
   ./build-xcframework.sh
   ```

   This needs `rustup` and Xcode's command line tools. It cross-compiles
   `passlib_ffi` for macOS (arm64 + x86_64), iOS device (arm64), and iOS
   Simulator (arm64 + x86_64), then assembles them into
   `PassKitFFI.xcframework` next to this README. Without this step,
   `Package.swift` fails to resolve — that failure is expected, not a bug.

2. **Create the Xcode project shell.** This repo intentionally does not
   include a hand-written `.xcodeproj` — that file format is binary-ish
   and fragile enough that generating it without Xcode itself to verify it
   opens felt riskier than just telling you the two-minute path:

   - File → New → Project → **Multiplatform → App** (this template gives
     you one shared source set building both a macOS and an iOS target,
     which is exactly the `App/` layout here).
   - Product name `Pass`, interface **SwiftUI**.
   - Delete the template's generated `ContentView.swift` and `PassApp.swift`.
   - Drag `Pass/App/` (all of it, including `Views/`) and `Shared/` into
     the project, for both targets; delete the template's own
     entitlements file (`Config/App.xcconfig` points at
     `Pass/Pass.entitlements` instead).
   - File → Add Package Dependencies → **Add Local...** → select this
     `pass-apple/` directory (the one with `Package.swift`) → add the
     `PassKit` product to both the macOS and iOS targets.

3. **Base configurations and signing.** In the project's Info tab, set
   the app target's configurations to `Config/App.xcconfig` (save the
   project inside `pass-apple/`, since the xcconfigs use paths relative to
   it). Pick your team under *Signing & Capabilities*: everything that
   needs a Team ID — the App Group (`TEAMID.it.antoniopicone.Pass` on
   macOS, `group.it.antoniopicone.Pass` on iOS, which requires that
   prefix) and the keychain group (`TEAMID.it.antoniopicone.Pass`) — is
   derived from `DEVELOPMENT_TEAM`, so no Team ID lives in this repo. If
   automatic signing complains that the App Group isn't registered, add
   it under *Signing & Capabilities → App Groups* with that same value.

4. **AutoFill extension targets.** File → New → Target → **AutoFill
   Credential Provider Extension**, once for macOS and once for iOS
   (bundle IDs e.g. `it.antoniopicone.Pass.AutoFill`, embedded in the
   matching app). For each:
   - Delete the template's generated Swift file, storyboard and
     Info.plist; add this directory's `AutoFill/` and `Shared/` folders
     (add `Shared/` to the app targets too) and the `PassKit` package
     product.
   - Set its configurations to `Config/AutoFill.xcconfig`, which points at
     `AutoFill/Info.plist` and the right `AutoFill-*.entitlements` per
     platform (the macOS extension must be sandboxed; it reads the vault
     only through the App Group).

5. **Bundle the CLI and the Chromium native host (macOS).** In the macOS
   app target's Build Phases add a *Run Script* phase running
   `"${SRCROOT}/Scripts/bundle-helpers.sh"`. It builds `pass` and
   `pass-native-host` for the architectures being built, copies them into
   `Pass.app/Contents/Helpers/` and signs them with the app's identity and
   App Group (`ENABLE_USER_SCRIPT_SANDBOXING = NO` is already in
   `App.xcconfig` so it can read the Rust workspace). Then:

   ```bash
   chrome-extension/native-host/install.sh <extension-id>   # picks /Applications/Pass.app's helper
   sudo ln -sf /Applications/Pass.app/Contents/Helpers/pass /usr/local/bin/pass   # optional
   ```

6. **macOS App Sandbox stays off for the app** (`Pass/Pass.entitlements`
   doesn't enable it): the app must still be able to open a vault picked
   anywhere on disk and move it into the App Group container. Only the
   AutoFill extension is sandboxed.

7. **iOS Photos permission.** The MFA QR-photo scanner uses `PhotosPicker`,
   which does not need `NSPhotoLibraryUsageDescription` (it runs out of
   process), so no Info.plist entry should be required — but if Xcode
   complains, add that key with a short description.

8. Build and run. Report back what broke — it's genuinely useful signal
   for this repo, since it's the only client that's shipped without a
   compiler having looked at it first.

## AutoFill: using Pass instead of Apple Passwords

Once the app runs, turn Pass on in *Settings → General → AutoFill &
Passwords* (iOS) or *System Settings → General → AutoFill & Passwords*
(macOS 15+), and turn Passwords off there if you want Pass to be the only
one.

- **What it fills:** logins (suggested above the keyboard / under the
  field, and the full searchable list) and, from iOS 18 / macOS 15, TOTP
  verification codes in one-time-code fields.
- **Unlocking:** the extension opens the vault with the master password
  kept behind Face ID/Touch ID — the same keychain item the app stores
  when you enable biometric unlock, shared through the keychain group — or
  with the typed master password.
- **Suggestions without unlocking:** after every change the app (and the
  extension, whenever it unlocks) refreshes `ASCredentialIdentityStore`
  with site, username and entry ID only — never passwords or TOTP secrets.
- **Where the vault must be:** in the App Group container, the only place
  the sandboxed extension can read. New vaults go there by default; an
  existing one can be moved from *Settings → Move Vault to Shared
  Container*, which also points the CLI and the Chromium native host at it
  (`~/.config/pass/last-vault`).
- **Chrome on macOS:** Chrome doesn't use AutoFill providers for
  passwords, so the Chromium extension stays. Its native host, bundled and
  team-signed inside Pass.app, opens the vault in the App Group container
  directly. An unbundled `cargo build` of it (or of the CLI) still works,
  but macOS 15+ may ask for permission to access another app's data, and
  that consent only lasts while the process runs.
- **Not covered yet:** saving new passwords from Safari's sign-up forms
  (Apple only offers that to providers from iOS 26.2, `ASSavePasswordRequest`),
  passkeys, and importing through Credential Exchange (iOS/macOS 26) —
  the CSV import covers that for now.

## Design notes

- **Same vault, same format.** `AppState`'s default vault path is
  `personal.kdbx` in the App Group container (both platforms; Documents
  if the build has no team) — a real KDBX4 file, openable
  by `pass`, `pass-gnome`, and KeePassXC itself. See the main README's
  "KDBX4 / KeePassXC compatibility" section for the field mapping.
- **No custom merge logic here either.** `Vault.merge(fromFile:)` calls
  straight into `vault_merge_from_file`, which is backed by
  `keepass::Database::merge` — a one-off import tool for an *unrelated*
  KDBX file, unrelated to cross-device sync of this same vault (see next).
- **No custom sync logic here either, again.** `Vault.syncPull()` is a thin
  wrapper over `vault_sync_pull`, backed by `passlib::sync::SyncHandle` —
  the exact same encrypted push/pull client every other `pass` frontend
  uses against the local `pass-syncd` daemon. `AppState`'s `startSyncTimer`
  polls it every 3s while unlocked; every mutating `Vault` method already
  pushes its own change automatically (baked into `passlib_ffi` itself), so
  nothing on the Swift side needed to change for that half.
- **Joining an existing synced vault from scratch.** Right after
  `AppState.createVault` succeeds, `Vault.checkSyncImportAvailable()`
  (`vault_check_sync_import_available`, no vault handle needed) checks
  whether `pass-syncd` already knows of one from another device; if so,
  `RootView`'s `syncImportOffer` alert offers `Vault.importFromSync()`
  (`vault_import_from_sync`), which adopts that vault's exact sync salt
  and pulls in every entry the mesh has — see the main README's
  "Cross-device sync" section and `pass-syncd/README.md`'s "Joining from a
  brand-new device".
- **iOS file picking copies into the app's own Documents directory**
  (`AppState.importVaultFile`) rather than holding onto a security-scoped
  URL across the whole session, since the vault stays "open" across many
  separate FFI calls, not one bounded read. macOS uses the picked path
  directly (see the sandbox note above).
- **QR scanning uses Vision (`VNDetectBarcodesRequest`)**, not a
  third-party library — it's built into iOS/macOS, so `TOTPAttachView`
  needs nothing beyond `PhotosUI` and `Vision`.
