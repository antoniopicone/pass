#!/usr/bin/env python3
"""End-to-end test suite for the Pass Chromium extension.

Drives a real Brave/Chrome instance over the DevTools protocol (no mocking):
creates a real vault, exercises the popup UI, and checks the in-page
autofill/save content-script behavior against real HTML fixtures — including
a strict Trusted-Types CSP page, matching sites like accounts.google.com.

Normally run via ../run_tests.sh, which also runs `cargo test` and takes
care of the one-time setup below. To run this script directly instead:

    pip install -r requirements.txt
    ../native-host/install.sh "$(python3 run_tests.py --print-extension-id)"
    python3 run_tests.py                # uses Brave if found, else Chrome
    python3 run_tests.py --browser Chrome

Run this before packaging a release.
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(__file__))
import cdp
import server

EXT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(EXT_DIR)
FIXTURE_PORT = 8899

BROWSER_PATHS = {
    "Brave": "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "Chrome": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "Chromium": "/Applications/Chromium.app/Contents/MacOS/Chromium",
}

PASS = []
FAIL = []


def extension_id_from_key(manifest_path):
    """Same derivation Chrome itself uses: first 16 bytes of SHA-256(DER
    public key), each nibble mapped to a-p."""
    manifest = json.load(open(manifest_path))
    key_b64 = manifest["key"]
    der = base64.b64decode(key_b64)
    digest = hashlib.sha256(der).digest()[:16]
    return "".join(chr(ord("a") + (b >> 4)) + chr(ord("a") + (b & 0xF)) for b in digest)


def find_browser(preferred=None):
    if preferred:
        path = BROWSER_PATHS.get(preferred)
        if path and os.path.exists(path):
            return path
        sys.exit(f"Browser '{preferred}' not found at {path}")
    for name, path in BROWSER_PATHS.items():
        if os.path.exists(path):
            return path
    sys.exit("No supported browser found (looked for Brave, Chrome, Chromium).")


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  \033[32m✓\033[0m {name}")
    else:
        FAIL.append((name, detail))
        print(f"  \033[31m✗\033[0m {name}  {detail}")


def wait_for_devtools(timeout=15):
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(cdp.BASE + "/json/version", timeout=1)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", choices=list(BROWSER_PATHS), default=None)
    parser.add_argument("--keep-open", action="store_true", help="leave the browser running after tests")
    parser.add_argument("--print-extension-id", action="store_true",
                         help="print the extension ID derived from manifest.json's fixed key and exit "
                              "(used by run_tests.sh to register the native host)")
    args = parser.parse_args()

    manifest_path = os.path.join(EXT_DIR, "manifest.json")
    ext_id = extension_id_from_key(manifest_path)

    if args.print_extension_id:
        print(ext_id)
        return

    print(f"Extension ID: {ext_id}")

    browser_path = find_browser(args.browser)
    print(f"Browser: {browser_path}")

    httpd = server.start(FIXTURE_PORT)
    print(f"Fixture server: http://localhost:{FIXTURE_PORT}")

    profile_dir = tempfile.mkdtemp(prefix="pass-ext-test-profile-")
    cdp.BASE = "http://localhost:9333"
    proc = subprocess.Popen(
        [
            browser_path,
            "--remote-debugging-port=9333",
            "--remote-allow-origins=*",
            f"--user-data-dir={profile_dir}",
            f"--load-extension={EXT_DIR}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        if not wait_for_devtools():
            sys.exit("Browser did not become ready — did loading the extension hang? "
                     "(a malformed _locales/*/messages.json placeholder is a known past cause; "
                     "see chrome-extension/README.md's Testing section)")

        vault_path = os.path.join(tempfile.mkdtemp(prefix="pass-ext-test-vault-"), "passwords.kdbx")
        run_all(ext_id, vault_path)
    finally:
        proc_alive = proc.poll() is None
        if args.keep_open and proc_alive:
            print("\n--keep-open set: leaving the browser running. Kill it manually when done.")
        elif proc_alive:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        httpd.shutdown()

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("\nFailed:")
        for name, detail in FAIL:
            print(f"  - {name}: {detail}")
        sys.exit(1)


def run_all(ext_id, vault_path):
    popup_url = f"chrome-extension://{ext_id}/popup.html"

    # A dedicated extension-origin tab used only for chrome.i18n.getMessage()
    # lookups. content.js runs in an isolated JS world; Runtime.evaluate
    # against a page (without targeting that specific execution context) runs
    # in the *main* world instead, where `chrome` is undefined — so any
    # translated-string assertion against a fixture page resolves through
    # this tab rather than the page under test. The suite deliberately never
    # hardcodes an expected English string: chrome.i18n picks the locale from
    # the OS/browser UI language (English or Italian here — see _locales/),
    # which a `--lang` browser flag does not reliably override. Asserting
    # against whatever the running browser actually resolves keeps the suite
    # correct regardless of the machine's locale, while still catching real
    # regressions (a wrong key, a broken placeholder).
    i18n_tab_id, i18n_t = cdp.open_tab(popup_url)
    i18n_t.send("Runtime.enable")
    time.sleep(1)

    def tr(key, substitutions=None):
        subs_js = json.dumps(substitutions) if substitutions else "undefined"
        return i18n_t.eval(f"chrome.i18n.getMessage({key!r}, {subs_js})")

    # ---------- 1. Vault lifecycle + i18n sanity ----------
    print("\n[1] Vault lifecycle")
    tab_id, t = cdp.open_tab(popup_url)
    t.send("Runtime.enable")
    time.sleep(1)

    check("popup shows locked view before unlocking", t.eval("document.getElementById('list-view').hidden") is True)

    t.eval(f"document.getElementById('vault-path').value = {vault_path!r}")
    t.eval("document.getElementById('master-password').value = 'test master password 2024'")
    t.eval("document.getElementById('init-btn').click()")
    time.sleep(1.5)
    check("vault created and unlocked", t.eval("document.getElementById('list-view').hidden") is False,
          t.eval("document.getElementById('status').textContent"))
    unlock_label = t.eval("document.getElementById('unlock-btn').textContent")
    check("i18n: data-i18n wiring resolves the locale's real string, not the raw key",
          unlock_label == tr("action_unlock") and unlock_label != "action_unlock", unlock_label)

    # ---------- 2. Add entry with notes + additional URLs ----------
    print("\n[2] Notes + additional URLs + favicon")
    t.eval("document.getElementById('fab-add').click()")
    time.sleep(0.3)
    t.eval("document.getElementById('add-website').value = 'Apple'")
    t.eval("document.getElementById('add-url').value = 'https://appleid.apple.com'")
    t.eval("document.getElementById('add-username').value = 'me@example.com'")
    t.eval("document.getElementById('add-password').value = 'FirstPassword1!'")
    t.eval(r"document.getElementById('add-additional-urls').value = 'icloud.com\naccount.apple.com'")
    t.eval("document.getElementById('add-notes').value = 'Recovery key: ABCD-1234'")
    t.eval("document.getElementById('add-save-btn').click()")
    time.sleep(1)
    entries_text = t.eval("document.getElementById('entry-list').innerText")
    check("entry appears in list", "Apple" in entries_text, entries_text)

    t.eval("document.querySelector('#entry-list .entry').click()")
    time.sleep(0.8)
    check("notes row shown", t.eval("document.getElementById('detail-notes-row').hidden") is False)
    check("notes content correct",
          t.eval("document.getElementById('detail-notes').textContent") == "Recovery key: ABCD-1234")
    check("additional URLs row shown", t.eval("document.getElementById('detail-additional-urls-row').hidden") is False)
    check("additional URLs content correct",
          "icloud.com" in t.eval("document.getElementById('detail-additional-urls').textContent"))
    favicon_src = t.eval("document.getElementById('detail-avatar').querySelector('img')?.src") or ""
    check("favicon uses the registrable (2nd-level) domain, not the exact subdomain",
          "pageUrl=https%3A%2F%2Fapple.com" in favicon_src, favicon_src)

    apple_entry_id = t.eval("""
        new Promise(r => chrome.runtime.sendMessage({type:'PASS_GET_STATE'}, res => r(res.result.entries[0].id)))
    """, await_promise=True)

    # ---------- 3. Password history ----------
    print("\n[3] Password history")
    check("history card hidden before any password change",
          t.eval("document.getElementById('detail-history-card').hidden") is True)

    t.eval("document.getElementById('detail-edit-btn').click()")
    time.sleep(0.2)
    t.eval("document.getElementById('edit-password').value = 'SecondPassword2@'")
    t.eval("document.getElementById('edit-save-btn').click()")
    time.sleep(1.0)
    check("history card visible after 1 password change",
          t.eval("document.getElementById('detail-history-card').hidden") is False)
    check("history summary shows 1 entry",
          "1" in (t.eval("document.getElementById('detail-history-summary').textContent") or ""))

    t.eval("document.getElementById('detail-edit-btn').click()")
    time.sleep(0.2)
    t.eval("document.getElementById('edit-password').value = 'ThirdPassword3#'")
    t.eval("document.getElementById('edit-save-btn').click()")
    time.sleep(1.0)
    check("history summary shows 2 entries after a 2nd change",
          "2" in (t.eval("document.getElementById('detail-history-summary').textContent") or ""))

    t.eval("document.getElementById('detail-history-toggle').click()")
    time.sleep(0.2)
    t.eval("document.querySelectorAll('#detail-history-list .history-item .icon-btn')[0].click()")
    time.sleep(0.2)
    revealed = t.eval("document.querySelectorAll('.history-password')[0].textContent")
    check("revealed history password matches an actual previous password",
          revealed in ("FirstPassword1!", "SecondPassword2@"), revealed)

    # ---------- 4. Multi-site entry for autofill/matching tests ----------
    t.eval("document.getElementById('detail-back-btn').click()")
    time.sleep(0.2)
    t.eval("document.getElementById('fab-add').click()")
    time.sleep(0.3)
    t.eval("document.getElementById('add-website').value = 'Test Login Page'")
    t.eval(f"document.getElementById('add-url').value = 'http://localhost:{FIXTURE_PORT}/login.html'")
    t.eval("document.getElementById('add-username').value = 'alice@example.com'")
    t.eval("document.getElementById('add-password').value = 'S3cretPass!2024'")
    t.eval("document.getElementById('add-save-btn').click()")
    time.sleep(1)

    t.eval("document.getElementById('fab-add').click()")
    time.sleep(0.3)
    t.eval("document.getElementById('add-website').value = 'MultiSite'")
    t.eval("document.getElementById('add-url').value = 'https://unrelated.example'")
    t.eval("document.getElementById('add-username').value = 'multi@example.com'")
    t.eval("document.getElementById('add-password').value = 'MultiSitePw1!'")
    t.eval(f"document.getElementById('add-additional-urls').value = 'localhost'")
    t.eval("document.getElementById('add-save-btn').click()")
    time.sleep(1)

    cdp.close_tab(tab_id)

    # ---------- 5. In-page autofill (real content script, real page) ----------
    print("\n[4] In-page autofill")
    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/login.html")
    t.send("Runtime.enable")
    time.sleep(1.5)
    check("marker attached to the password field",
          t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelectorAll('.marker').length") == 1)

    t.eval("""
        document.getElementById('pass-extension-root').shadowRoot.querySelector('.marker')
          .dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true}))
    """)
    time.sleep(1.0)
    dropdown_text = t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelector('.dropdown')?.innerText") or ""
    check("dropdown lists both matching entries (direct URL + additionalUrls match)",
          "Test Login Page" in dropdown_text and "MultiSite" in dropdown_text, dropdown_text)

    t.eval("""
        [...document.getElementById('pass-extension-root').shadowRoot.querySelectorAll('.dropdown-item')]
          .find(el => el.textContent.includes('alice@example.com'))
          .dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true}))
    """)
    time.sleep(1.0)  # native host round-trip: fresh process + KDBX4 KDF on every call
    check("autofill filled the username field", t.eval("document.getElementById('email').value") == "alice@example.com")
    check("autofill filled the password field", t.eval("document.getElementById('password').value") == "S3cretPass!2024")
    cdp.close_tab(tab_id)

    # ---------- 6. Signup: password generation + save prompt ----------
    print("\n[5] Signup: generated password + save prompt")
    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/signup.html")
    t.send("Runtime.enable")
    time.sleep(1.5)

    t.eval("""
        (() => {
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
          const email = document.getElementById('email');
          setter.call(email, 'carol.new@example.com');
          email.dispatchEvent(new Event('input', {bubbles: true}));
        })()
    """)
    # Find-and-dispatch in a single Runtime.evaluate: splitting this into two
    # round-trips was observed to occasionally miss the marker (the dropdown
    # click below showed the *previous* dropdown state) — keeping it atomic
    # avoids that race.
    found = t.eval("""
        (() => {
          const markers = [...document.getElementById('pass-extension-root').shadowRoot.querySelectorAll('.marker')];
          const pwRect = document.getElementById('password').getBoundingClientRect();
          const marker = markers.find(m => Math.abs(m.getBoundingClientRect().top - pwRect.top) < 40);
          if (!marker) return false;
          marker.dispatchEvent(new MouseEvent('mousedown', {bubbles:true, cancelable:true}));
          return true;
        })()
    """)
    check("marker found near the signup password field", found)
    time.sleep(1.0)

    use_suggested_label = tr("content_use_suggested_password")
    t.eval(f"""
        [...document.getElementById('pass-extension-root').shadowRoot.querySelectorAll('.dropdown-item')]
          .find(el => el.textContent.includes({use_suggested_label!r}))
          .dispatchEvent(new MouseEvent('mousedown', {{bubbles:true, cancelable:true}}))
    """)
    time.sleep(0.3)
    pw1 = t.eval("document.getElementById('password').value")
    pw2 = t.eval("document.getElementById('password2').value")
    check("generated password meets length/complexity", len(pw1 or "") >= 20)
    check("confirm-password field auto-filled with the same generated password", bool(pw1) and pw1 == pw2)

    t.eval("document.getElementById('signup-form').dispatchEvent(new Event('submit', {bubbles:true, cancelable:true}))")
    time.sleep(1.2)
    toast_text = t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelector('.toast')?.innerText") or ""
    check("save-password toast appears after signup submit", tr("content_save_title") in toast_text, toast_text)

    save_label = tr("content_save")
    t.eval(f"""
        [...document.getElementById('pass-extension-root').shadowRoot.querySelectorAll('.toast-btn')]
          .find(b => b.textContent.trim() === {save_label!r}).click()
    """)
    time.sleep(1.0)
    cdp.close_tab(tab_id)

    tab_id, t = cdp.open_tab(popup_url)
    t.send("Runtime.enable")
    time.sleep(1)
    entries_text = t.eval("document.getElementById('entry-list').innerText")
    check("new entry from the signup save-prompt was actually persisted to the vault",
          "carol.new@example.com" in entries_text, entries_text)
    cdp.close_tab(tab_id)

    # ---------- 7. Update-password prompt ----------
    print("\n[6] Login with a changed password triggers an update prompt")
    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/login.html")
    t.send("Runtime.enable")
    time.sleep(1.5)
    t.eval("""
        (() => {
          const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
          const email = document.getElementById('email');
          setter.call(email, 'alice@example.com');
          email.dispatchEvent(new Event('input', {bubbles:true}));
          const pw = document.getElementById('password');
          setter.call(pw, 'BrandNewPassword#99');
          pw.dispatchEvent(new Event('input', {bubbles:true}));
        })()
    """)
    t.eval("document.getElementById('login-form').dispatchEvent(new Event('submit', {bubbles:true, cancelable:true}))")
    time.sleep(1.2)
    toast_text = t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelector('.toast')?.innerText") or ""
    check("update-password toast appears for a known username with a new password",
          tr("content_update_title") in toast_text, toast_text)
    update_label = tr("content_update")
    t.eval(f"""
        [...document.getElementById('pass-extension-root').shadowRoot.querySelectorAll('.toast-btn')]
          .find(b => b.textContent.trim() === {update_label!r}).click()
    """)
    time.sleep(1.0)
    cdp.close_tab(tab_id)

    # ---------- 8. Trusted Types compatibility ----------
    print("\n[7] Trusted Types CSP compatibility (accounts.google.com-style)")
    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/trusted-types/email")
    t.send("Runtime.enable")
    time.sleep(1.5)
    check("marker attaches on a page with require-trusted-types-for CSP (email-only step)",
          t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelectorAll('.marker').length") == 1)
    cdp.close_tab(tab_id)

    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/trusted-types/password")
    t.send("Runtime.enable")
    time.sleep(1.5)
    check("marker attaches to the *visible* password field, not the CSS-clipped decoy",
          t.eval("document.getElementById('pass-extension-root')?.shadowRoot?.querySelectorAll('.marker').length") == 1)
    field_bottom = t.eval("document.getElementById('pw').getBoundingClientRect().bottom")
    marker_bottom = t.eval("""
        document.getElementById('pass-extension-root').shadowRoot.querySelector('.marker').getBoundingClientRect().bottom
    """)
    check("marker is positioned within the real (visible) field's vertical bounds",
          abs(field_bottom - marker_bottom) < 40, f"field_bottom={field_bottom} marker_bottom={marker_bottom}")
    cdp.close_tab(tab_id)

    # ---------- 9. Marker sizing on a very small field ----------
    print("\n[8] Marker never overflows a small field")
    tab_id, t = cdp.open_tab(f"http://localhost:{FIXTURE_PORT}/tiny_field.html")
    t.send("Runtime.enable")
    time.sleep(1.5)
    fits = t.eval("""
        JSON.stringify((() => {
          const field = document.getElementById('tiny');
          const rect = field.getBoundingClientRect();
          const root = document.getElementById('pass-extension-root');
          const marker = [...root.shadowRoot.querySelectorAll('.marker')]
            .find(m => Math.abs(m.getBoundingClientRect().top - rect.top) < 30);
          if (!marker) return {found: false};
          const mr = marker.getBoundingClientRect();
          return {
            found: true,
            fitsVertically: mr.top >= rect.top - 0.5 && mr.bottom <= rect.bottom + 0.5,
            fitsHorizontally: mr.right <= rect.right + 0.5,
          };
        })())
    """)
    fits = json.loads(fits)
    check("marker found on the tiny field", fits.get("found"))
    check("marker fits within the field vertically (no overflow)", fits.get("fitsVertically"), fits)
    check("marker fits within the field horizontally (no overflow)", fits.get("fitsHorizontally"), fits)
    cdp.close_tab(tab_id)

    # ---------- 10. Delete entry (Recycle Bin) ----------
    print("\n[9] Delete entry")
    tab_id, t = cdp.open_tab(popup_url)
    t.send("Runtime.enable")
    time.sleep(1)
    t.eval(f"""
        new Promise((resolve) => {{
          chrome.runtime.sendMessage({{type: 'PASS_DELETE_ENTRY', payload: {{id: {apple_entry_id!r}}}}}, resolve);
        }})
    """, await_promise=True)
    time.sleep(1)
    entries_text = t.eval("""
        new Promise(r => chrome.runtime.sendMessage({type:'PASS_GET_STATE'}, res => r(JSON.stringify(res.result.entries.map(e => e.website)))))
    """, await_promise=True)
    check("deleted entry no longer appears in the active list", "Apple" not in entries_text, entries_text)
    cdp.close_tab(tab_id)

    cdp.close_tab(i18n_tab_id)


if __name__ == "__main__":
    main()
