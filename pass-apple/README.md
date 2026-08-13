# Pass — macOS / iOS clients

A shared SwiftUI app (unlock/create vault, search, view/reveal/copy
password and MFA code with a live countdown, add/edit/delete, attach MFA
via `otpauth://` URI or a QR code photo, merge another vault copy) backed
by `passlib_ffi` — the same Rust core `pass`, `pass-gnome`, and the
Chromium extension use, opening the same real KDBX4/KeePassXC-compatible
`.kdbx` files.

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
├── Sources/PassKit/           Swift wrapper around passlib_ffi.h (Vault, PasswordEntry, errors)
└── App/                       Shared SwiftUI source for both the macOS and iOS app targets
    ├── PassApp.swift          @main entry point
    ├── RootView.swift         Locked ⇄ unlocked switch
    ├── AppState.swift         ObservableObject driving all vault operations
    ├── Clipboard.swift        Cross-platform copy-to-clipboard
    └── Views/                 Unlock, entry list, entry detail, add/edit form, MFA attach, merge
```

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
   - Drag this directory's `App/` folder (all of it, including `Views/`)
     into the project, for both targets.
   - File → Add Package Dependencies → **Add Local...** → select this
     `pass-apple/` directory (the one with `Package.swift`) → add the
     `PassKit` product to both the macOS and iOS targets.

3. **macOS entitlements.** If the macOS target has App Sandbox enabled
   (Xcode's default for new Mac targets), add the
   *"App Sandbox → File Access → User Selected File → Read/Write"*
   entitlement, or the vault-path file picker won't be able to read/write
   arbitrary paths. Simplest alternative for a first build: turn App
   Sandbox off for this personal-use app.

4. **iOS Photos permission.** The MFA QR-photo scanner uses `PhotosPicker`,
   which does not need `NSPhotoLibraryUsageDescription` (it runs out of
   process), so no Info.plist entry should be required — but if Xcode
   complains, add that key with a short description.

5. Build and run. Report back what broke — it's genuinely useful signal
   for this repo, since it's the only client that's shipped without a
   compiler having looked at it first.

## Design notes

- **Same vault, same format.** `AppState`'s default vault path is
  `Documents/passwords.kdbx` (both platforms) — a real KDBX4 file, openable
  by `pass`, `pass-gnome`, and KeePassXC itself. See the main README's
  "KDBX4 / KeePassXC compatibility" section for the field mapping.
- **No custom merge logic here either.** `Vault.merge(fromFile:)` calls
  straight into `vault_merge_from_file`, which is backed by
  `keepass::Database::merge` — the same cross-device reconciliation `pass
  merge`/`pass watch` use.
- **iOS file picking copies into the app's own Documents directory**
  (`AppState.importVaultFile`) rather than holding onto a security-scoped
  URL across the whole session, since the vault stays "open" across many
  separate FFI calls, not one bounded read. macOS uses the picked path
  directly (see the sandbox note above).
- **QR scanning uses Vision (`VNDetectBarcodesRequest`)**, not a
  third-party library — it's built into iOS/macOS, so `TOTPAttachView`
  needs nothing beyond `PhotosUI` and `Vision`.
