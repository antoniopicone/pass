# Pass — Chromium Extension

A Manifest V3 extension that unlocks your local `pass` vault, lets you
search/copy/autofill entries from the popup, and can pull in changes merged
from another synced copy of the vault (e.g. one kept in a Nextcloud folder).

It never talks to the network itself. All vault access goes through a small
native messaging host (`pass-native-host`, built from this repo) that Chrome
launches as a subprocess and talks to over stdio — the master password is
typed into the popup and passed to that local process, never sent anywhere
else.

## How it fits together

```
popup.js / content.js  <-- chrome.runtime.sendNativeMessage -->  pass-native-host  <-->  passlib (vault file on disk)
```

Every popup action (unlock, list, get, add, update, delete, merge) is a
single stateless request: the host opens the vault file with the supplied
master password, does the operation, saves if needed, and replies. Nothing
is kept unlocked in the background between calls — the popup itself caches
the master password in `chrome.storage.session` for 5 minutes so you don't
have to retype it every time you reopen the popup, and that cache is wiped
when the browser closes.

## Setup

1. **Build and register the native host.** From the repo root:

   ```bash
   chrome-extension/native-host/install.sh <extension-id>
   ```

   You need the extension ID for this, which you only get after loading the
   extension once (step 2) — so do step 2 first, copy the ID shown on
   `chrome://extensions`, then come back and run this script. Re-run it
   whenever the extension ID changes.

2. **Load the extension.** Open `chrome://extensions` (or
   `chrome://extensions` in any Chromium-based browser), enable
   *Developer mode*, click *Load unpacked*, and select the
   `chrome-extension/` directory.

3. **Open the popup**, enter the path to your vault file (the same file
   `pass` uses, e.g. `/home/you/passwords.vault`) and your master password,
   and click **Unlock** (or **Create new vault** if it doesn't exist yet).

## Using it

- The entry list is sorted so matches for the current tab's domain float to
  the top.
- **Fill** sends the decrypted username/password to the active tab's
  content script, which fills the best-guess login fields on the page. It
  never submits the form.
- **Copy** copies the password to the clipboard.
- The **Merge another vault copy** panel lets you point at a second copy of
  the vault file — e.g. the one synced into a local Nextcloud folder on this
  machine — and merge it into the currently unlocked vault. This exercises
  the same per-entry, revision-based merge used by `pass merge` on the CLI:
  the newest edit to each entry wins, deletions propagate as tombstones,
  and true conflicts (the same entry edited on two devices before either
  saw the other's change) are resolved deterministically. See
  `passlib/src/merge.rs` for the algorithm.

## Limitations / not included here

This ships the vault access + merge-algorithm plumbing and a usable
autofill UI. It does **not** include:

- Talking to Nextcloud's WebDAV API directly, or watching the filesystem
  for remote changes — today you merge on demand by pointing at a second
  vault file path. Wiring that path to a live Nextcloud sync folder (or to
  WebDAV directly) with a file-watcher-triggered auto-merge is a natural
  next step, not implemented yet.
- Extension icons (Chrome falls back to a generic icon).
- Packaging/signing for the Chrome Web Store — this is meant to be loaded
  unpacked for personal use.
