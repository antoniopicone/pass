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

## Verification status

This code was first written in a Linux sandbox with no Apple toolchain, so
for a while nothing here had been compiled. That's no longer the case, but
what has and hasn't been exercised is worth knowing:

- **Built and checked** (Xcode 27, Apple Silicon): the quick macOS build
  (`build-macos-app.sh`); the generated Xcode project for macOS (universal,
  AutoFill extension embedded), the iOS Simulator and an iOS device, the
  last two unsigned; the iOS app launched in a simulator up to the unlock
  screen.
- **Not verified yet:** anything that needs a real signature and its
  entitlements — the team-signed build itself, the AutoFill extension at
  run time, Touch ID/Face ID unlock, the App Group container, the bundled
  CLI and native host — and running on a physical iOS device.

## What's here

```
pass-apple/
├── Package.swift              SPM package: PassKitFFI (binary) + PassKit (Swift wrapper)
├── build-xcframework.sh       Run on macOS: builds passlib_ffi for all Apple targets → PassKitFFI.xcframework
├── build-macos-app.sh         Run on macOS: builds a runnable .build/Pass.app without an Xcode project
├── build-xcode.sh             Run on macOS: xcframework + Pass.xcodeproj (XcodeGen) + optional xcodebuild
├── project.yml                XcodeGen spec for Pass.xcodeproj (the project itself is generated, git-ignored)
├── Sources/PassKit/           Swift wrapper around passlib_ffi.h (Vault, PasswordEntry, errors)
├── Config/                    xcconfigs: App Group + keychain group derived from DEVELOPMENT_TEAM (Local.xcconfig)
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

## Which build do I need?

There are two ways to build this, and they don't produce the same app:

| | Quick build | Xcode build |
|---|---|---|
| Platforms | macOS | macOS and iOS |
| Needs | Xcode installed, Rust | Xcode, Rust, XcodeGen, an Apple Developer team |
| Script | `./build-macos-app.sh` | `./build-xcode.sh [macos\|ios-sim\|ios]` |
| Rust core | `libpasslib_ffi.a`, built by the script | `PassKitFFI.xcframework` (`build-xcframework.sh`) |
| Signing | ad-hoc, no entitlements | your team, App Group + keychain group |
| Vault, search, MFA, import, sync | yes | yes |
| Touch ID / Face ID unlock | no | yes |
| AutoFill extension | no | yes |
| CLI + Chromium host bundled in Pass.app | no | yes (macOS) |

The top-level `./install.sh` picks between them on macOS and copies the
result to `/Applications`: the Xcode build if a team is configured (see
below), the quick build otherwise — which never replaces a team-signed
Pass.app already there. `./install.sh --xcode` also generates
`Pass.xcodeproj`, for iOS or for working in Xcode.

## Quick macOS build (no Xcode project)

```bash
cd pass-apple
./build-macos-app.sh          # CONFIGURATION=debug / ARCH=x86_64 to override
open .build/Pass.app
```

This compiles `passlib_ffi`, `PassKit`, `Shared/` and `Pass/App/` directly
with `cargo`/`swiftc` and assembles an ad-hoc signed `Pass.app` (menu bar
icon included). It needs Xcode with its license accepted, but not the
xcframework or an `.xcodeproj`. It's signed without `Pass.entitlements`,
because the App Group and `keychain-access-groups` need a real team ID:
the vault defaults to `~/Documents/personal.kdbx` instead of the App Group
container, and enabling Touch ID unlock fails (the keychain refuses the
item with `errSecMissingEntitlement`). Use the Xcode build below for a
properly signed app, and for iOS.

## Xcode build (macOS with AutoFill, and iOS)

`Pass.xcodeproj` is not checked in: it's generated from `project.yml` by
[XcodeGen](https://github.com/yonaskolb/XcodeGen), so the versioned source
of truth is a file that can be read and diffed.

```bash
brew install xcodegen                 # once
cd pass-apple
echo 'DEVELOPMENT_TEAM = ABCDE12345' > Config/Local.xcconfig   # once: your Team ID

./build-xcode.sh                      # xcframework + Pass.xcodeproj → open Pass.xcodeproj
./build-xcode.sh macos                # ...and build Pass.app (Release, universal)
./build-xcode.sh ios-sim              # ...and build for the iOS Simulator (needs no team)
./build-xcode.sh ios                  # ...and build for an iOS device (Release)
```

Each run does, in order:

1. **`build-xcframework.sh`** cross-compiles `passlib_ffi` for macOS
   (arm64 + x86_64), iOS device (arm64) and iOS Simulator (arm64 +
   x86_64) into `PassKitFFI.xcframework`, which `Package.swift` needs to
   resolve. Needs `rustup`.
2. **`xcodegen generate`** writes `Pass.xcodeproj` with four targets —
   `Pass-macOS`, `Pass-iOS` and an `AutoFill-*` extension embedded in each
   — all on the same sources (`Pass/`, `AutoFill/`, `Shared/`) and the
   `PassKit` package. Re-run it after adding or moving files; don't edit
   the project's settings in Xcode, they'd be lost — change `project.yml`
   or `Config/*.xcconfig` instead.
3. **`xcodebuild`**, for `macos`/`ios-sim`/`ios`, into
   `.build/xcode/Build/Products/`. Anything after the action is passed to
   it. To run on an iPhone, open the project and run the `Pass-iOS` scheme
   with the device selected.

Notes:

- **Team and signing.** Everything that needs a Team ID — the App Group
  (`TEAMID.it.antoniopicone.Pass` on macOS, `group.it.antoniopicone.Pass`
  on iOS, which requires that prefix) and the keychain group
  (`TEAMID.it.antoniopicone.Pass`) — is derived from `DEVELOPMENT_TEAM` in
  `Config/Shared.xcconfig`, so no Team ID lives in this repo.
  `Config/Local.xcconfig` is git-ignored; exporting `DEVELOPMENT_TEAM`
  works too. Signing is automatic and `build-xcode.sh` passes
  `-allowProvisioningUpdates`, so your Apple ID must be signed in under
  Xcode → Settings → Accounts. If it complains that the App Group isn't
  registered, add it under *Signing & Capabilities → App Groups* with that
  same value. Without a team, `macos` and `ios` still compile, unsigned,
  as a check — with the same limits as the quick build.
- **CLI and Chromium native host (macOS).** A build phase runs
  `Scripts/bundle-helpers.sh`, which builds `pass` and `pass-native-host`
  for the architectures being built, copies them into
  `Pass.app/Contents/Helpers/` and signs them with the app's identity and
  App Group (`ENABLE_USER_SCRIPT_SANDBOXING = NO` in `App.xcconfig` lets
  it read the Rust workspace). Then:

  ```bash
  chrome-extension/native-host/install.sh <extension-id>   # picks /Applications/Pass.app's helper
  sudo ln -sf /Applications/Pass.app/Contents/Helpers/pass /usr/local/bin/pass   # optional
  ```

- **macOS App Sandbox stays off for the app** (`Pass/Pass.entitlements`
  doesn't enable it): the app must still be able to open a vault picked
  anywhere on disk and move it into the App Group container. Only the
  AutoFill extension is sandboxed.
- **iOS Photos permission.** The MFA QR-photo scanner uses `PhotosPicker`,
  which does not need `NSPhotoLibraryUsageDescription` (it runs out of
  process), so no Info.plist entry should be required — but if Xcode
  complains, add `INFOPLIST_KEY_NSPhotoLibraryUsageDescription` to the
  `Pass-iOS` target in `project.yml`.

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
