# Pass — Chromium Extension

A Manifest V3 extension that unlocks your local `pass` vault and gives you a
proper password-manager experience in the browser: a searchable entry list
with a NordPass-style detail view, a key icon on password fields that offers
your saved logins (or a strong generated password) right on the page, and a
"Save to Pass?" prompt when you submit a new or changed login.

It never talks to the network itself. All vault access goes through a small
native messaging host (`pass-native-host`, built from this repo) that Chrome
launches as a subprocess and talks to over stdio — the master password is
typed into the popup and passed to that local process, never sent anywhere
else.

## How it fits together

```
                     chrome.runtime.sendMessage
popup.js  ───────────────────────────────────┐
                                              ▼
content.js  ──────────────────────────►  background.js  <-- sendNativeMessage -->  pass-native-host  <-->  passlib (real .kdbx file on disk)
(in-page autofill / save prompts)      (owns the session)
```

`background.js` is the only piece that talks to the native host — content
scripts can't call `chrome.runtime.sendNativeMessage` themselves, so both the
popup and every page's content script relay through the background service
worker, which is also the single place holding the unlocked session.

Every vault action (unlock, list, get, add, update, delete, merge) is a
single stateless request from the host's point of view: it opens the vault
file with the supplied master password, does the operation, saves if needed,
and replies. Nothing is kept unlocked *in the native host* between calls —
the background service worker caches the master password in
`chrome.storage.session` for 5 minutes so you don't have to retype it every
time, and that cache is wiped when the browser closes.

## Setup

1. **Load the extension.** Open `chrome://extensions` (or the equivalent
   page in any Chromium-based browser — Brave, Edge, Chromium itself),
   enable *Developer mode*, click *Load unpacked*, and select the
   `chrome-extension/` directory.

   `manifest.json` pins a `"key"` (the extension's public key), so it
   always loads with the same fixed ID —
   **`pfboljglneiobfbnhoekhmfkilmjmdlg`** — instead of a random one that
   changes every reload. That's what makes step 2 a one-time setup instead
   of something to redo after every reload.

2. **Build and register the native host.**

   On macOS and Linux, from the repo root:

   ```bash
   chrome-extension/native-host/install.sh pfboljglneiobfbnhoekhmfkilmjmdlg
   ```

   On Windows, from PowerShell (no administrator rights needed):

   ```powershell
   .\chrome-extension\native-host\install.ps1 -ExtensionId pfboljglneiobfbnhoekhmfkilmjmdlg
   ```

   (If you swap in your own `"key"` in `manifest.json`, use the ID shown on
   `chrome://extensions` for *your* build instead.)

   Both scripts build `pass-native-host`, write a manifest JSON next to
   themselves, and point the browser at it. How the browser is pointed at it
   differs by platform: on macOS and Linux the manifest is copied into each
   browser's `NativeMessagingHosts` directory, while on Windows it stays put
   and a registry value under `HKCU\Software\...\NativeMessagingHosts`
   holds its path. Chrome, Chromium, Brave and Edge are all registered where
   they are installed.

   Quit the browser completely afterwards — every window, so the process
   really exits. Reloading the extension is not enough; the host list is read
   at browser startup.

3. **Open the popup**, enter the path to your vault file (the same real
   KDBX4 file `pass`/KeePassXC use, e.g. `/home/you/passwords.kdbx`) and
   your master password, and click **Unlock** (or **Create a new vault at
   this path** if it doesn't exist yet).

## Using it

- **The popup** is a searchable list (entries for the current tab's domain
  float to the top, tagged "this site"). Each entry shows the site's real
  favicon when Chrome already has one cached for it (via the `favicon`
  permission's `_favicon` endpoint — no network fetch of our own, no CORS),
  falling back to a colored-letter avatar otherwise; the lookup uses the
  *registrable* (second-level) domain — e.g. `apple.com`, not
  `idmsa.apple.com` — since that's normally where a site's real favicon is
  actually cached, and it keeps one consistent icon across an entry's
  several subdomains. Click an entry to open its detail view — reveal/copy
  the password, copy the username or URL, edit any field in place, manage
  its MFA code, or delete it (moves it to the vault's Recycle Bin). The
  **+** button adds a new entry by hand; **⋯ → Merge another vault copy** is
  unchanged from before.
- **Multiple sites, one entry.** An entry can list extra URLs under "Also
  match these sites" (one per line) besides its main URL — for accounts
  like Apple's that are the same login across several domains
  (`appleid.apple.com`, `icloud.com`, `account.apple.com`, …). Any of those
  URLs matches the entry for both the popup's "this site" sorting and the
  in-page dropdown/save-prompt, and they show on the detail view under
  "Also matches".
- **Notes.** A free-text field on every entry (e.g. a recovery key, a
  security question answer) — shown on the detail view only when non-empty,
  editable from the same edit screen as the other fields.
- **Password history.** Changing an entry's password keeps the previous
  ones (KDBX4's own history mechanism — the same one KeePassXC reads), shown
  as a collapsible "Password history" card on the detail view with a
  reveal/copy button per previous password. Nothing is deleted, and this
  works retroactively for entries created before this feature.
- **On the page itself**, every password field — and every standalone
  username/email field not already paired with one, e.g. Google's
  email-then-password sign-in split across two screens — gets a small key
  icon, inset evenly from the field's own edges and sized to the field's own
  height (14–20px, shrinking on short fields) so it never overflows a small
  input. Focusing the field (or clicking the icon) opens a dropdown with:
  - **Saved in Pass** — any entries matching the current site; click one to
    fill both the username and password fields (whichever of the two exist
    on the current screen).
  - **Suggested password** — shown on an empty password field (e.g. a
    signup form), with a real generated password (Web Crypto, mixed
    case/digits/symbols) that also fills any "confirm password" field in
    the same form. Click the refresh icon for a different one.
  - This is real integration with the page's own `<input>` elements (via
    the same native value setter React/Vue/etc. track), not just a popup
    action — it never submits the form itself. Note that this is Pass's
    *own* on-page dropdown, not the browser's native autofill panel (the
    one showing iCloud/Google-saved passwords) — no extension, from Pass to
    Bitwarden to 1Password, can add entries to that OS/browser-owned UI;
    third-party password managers all draw their own, same as this.
  - Built without `innerHTML` anywhere, since sites like
    `accounts.google.com` serve a `Content-Security-Policy:
    require-trusted-types-for 'script'` header that throws on *any*
    `innerHTML` write — including from a content script — which would
    otherwise silently kill the whole script before it attaches anything.
  - Field detection hit-tests each candidate field's own center point
    (`elementFromPoint`) rather than trusting `display`/`visibility`/size
    alone, since a real, on-screen-sized field can still be genuinely
    non-interactive — e.g. Apple's sign-in pre-renders the password step's
    `<input>` directly under the visible email field, inside a `height: 0;
    overflow: hidden` wrapper, until you advance past the email step. A
    field that exists but is briefly covered (a loading spinner during SPA
    hydration, say) at the moment of the initial scan is retried a few
    times shortly after load rather than only rescanning newly-added nodes.
- **Save/update prompts**: submitting a login or signup form (real `<form>`
  submit, Enter in a password field, or a login/signup-looking button
  click) with a username+password Pass doesn't already have — or already
  has under a different password — shows a small "Save password to Pass?"
  / "Update password in Pass?" toast in the corner of the page. This only
  happens while the vault is already unlocked in that browsing session;
  Pass never prompts for your master password from a webpage.
- Entries with an MFA secret show a 🔐 marker in the list; the detail view's
  MFA section shows the live code (with countdown) and a copy button, or
  **+ Add** to attach one by pasting an `otpauth://` URI (from a service's
  "can't scan the code?" manual-entry link — reading a QR image directly is
  CLI-only today, `pass totp add --qr <image>`).
- If a tab was already open before you installed/reloaded the extension, its
  content script isn't injected yet (normal Chrome behavior for any
  extension) — the popup's row-level Fill button detects this and injects it
  on demand automatically; the in-page key icon on that specific tab still
  needs a page reload to appear, same as any extension.

## Languages

The UI (popup and in-page dropdown/toast) follows the browser's own display
language via `chrome.i18n` — English and Italian are bundled today
(`_locales/en`, `_locales/it`; English is the fallback for any other
language). To add another language, copy `_locales/en/messages.json` to a
new `_locales/<code>/messages.json` and translate the `"message"` values
(leave the `"placeholders"` blocks alone — those wire up the `$NAME$`
substitutions like a username or a count, and every placeholder referenced
in a message's text must stay declared or the extension can hang the whole
browser at load time — see the Testing section below for how the test suite
catches this).

## Testing

`tests/run_tests.sh` runs everything worth checking before packaging a
build: the Rust workspace's own tests, then a real end-to-end pass over the
extension itself (creates a real vault, drives the actual popup UI and
content-script autofill/save-prompt behavior in a real Brave/Chrome window
via the DevTools protocol — no mocking). Run it from the repo root or from
`chrome-extension/tests/`:

```bash
chrome-extension/tests/run_tests.sh
```

First run creates a local virtualenv (`tests/.venv`, gitignored) and
installs `websocket-client` into it; later runs reuse it. It also builds and
registers `pass-native-host` for the extension's fixed ID, so a fresh
checkout needs no manual setup step beyond having Brave, Chrome, or Chromium
installed somewhere `run_tests.py` looks (pass `--browser Chrome` to force
one).

The suite covers: vault create/unlock, adding an entry with notes and
"also match these sites" URLs, password history after multiple changes
(including revealing an old password), in-page autofill against a real
fixture page (including the multi-URL match), password generation and the
save-prompt on a signup page, the update-prompt when logging in with a
changed password, Trusted Types CSP compatibility (a fixture replicating
`accounts.google.com`'s `require-trusted-types-for 'script'` header, plus
its "clipped pre-rendered field" pattern), the icon-sizing fix on a
genuinely small field, and deleting an entry. Every user-facing string
assertion resolves the expected text through the browser's own
`chrome.i18n.getMessage()` rather than hardcoding English, so the suite
passes regardless of the machine's locale.

Run just the Python suite (skipping the Rust tests and the venv/install
steps, e.g. once your virtualenv already exists) with
`tests/.venv/bin/python3 tests/run_tests.py`.

## Limitations / not included here

- Talking to Nextcloud's WebDAV API directly — this assumes a filesystem
  sync client (e.g. the Nextcloud desktop app) already keeps a copy of the
  vault up to date locally.
- Automatic merging from the extension itself. The CLI now has this
  (`pass watch <other-vault> --publish <path>`, see the main README) using
  real filesystem events, but wiring the same auto-merge into the browser
  (so the popup refreshes itself when another device's changes land)
  would need a persistent connection from the extension to the native
  host, which is awkward under Manifest V3's service worker lifecycle —
  not implemented here. Today you trigger the merge on demand from the
  popup's **Merge** panel, or just run `pass watch` alongside it.
- The save/update prompt's "is this a login/signup submission" detection is
  heuristic (real form submit, Enter, or a button whose text looks like
  login/signup/continue) — it covers plain `<form>` sites and typical SPA
  patterns, but an unusual custom auth flow could miss it. It only ever
  *offers* — nothing is saved without an explicit click.
- Extension icons (Chrome falls back to a generic icon).
- Packaging/signing for the Chrome Web Store — this is meant to be loaded
  unpacked for personal use.
