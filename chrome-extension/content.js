// In-page integration: a small key icon on password *and* username/email
// fields that opens a dropdown (matching saved logins for this site + a
// "use suggested password" option on password fields), plus detection of
// submitted login/signup forms to offer saving the credentials.
//
// All UI is built with plain DOM APIs (createElement/textContent/
// createElementNS) rather than innerHTML, and lives in a Shadow DOM host
// appended to <html>. Two reasons: it can't collide with the host page's
// CSS, and — importantly — many sites (accounts.google.com among them)
// serve a `Content-Security-Policy: require-trusted-types-for 'script'`
// header that makes the DOM throw on *any* `innerHTML` assignment, even
// from a content script sharing that document. An uncaught throw during
// the initial scan would abort the rest of this script, so the marker
// would silently never appear. Building nodes explicitly works everywhere.
//
// This script can't call chrome.runtime.sendNativeMessage itself — only
// background.js can — so every vault operation here is relayed through it
// via chrome.runtime.sendMessage.

(() => {
  function t(key, substitutions) {
    return chrome.i18n.getMessage(key, substitutions) || key;
  }

  const PROCESSED = new WeakSet();
  let shadowRoot = null;
  let dropdownEl = null;
  let markerPositionsDirty = false;
  const markers = new Map(); // field -> marker element

  // ---------- messaging ----------

  function sendToBackground(type, payload) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type, payload }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response || !response.ok) {
          reject(new Error((response && response.error) || "Unknown error."));
          return;
        }
        resolve(response.result);
      });
    });
  }

  // ---------- password generation (kept in sync with popup.js) ----------

  function generatePassword(length = 20) {
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digits = "0123456789";
    const symbols = "!@#$%^&*()-_=+[]{}";
    const all = lower + upper + digits + symbols;

    const randomChar = (charset) => {
      const bytes = new Uint32Array(1);
      crypto.getRandomValues(bytes);
      return charset[bytes[0] % charset.length];
    };

    const required = [randomChar(lower), randomChar(upper), randomChar(digits), randomChar(symbols)];
    const rest = Array.from({ length: Math.max(0, length - required.length) }, () => randomChar(all));
    const chars = [...required, ...rest];

    for (let i = chars.length - 1; i > 0; i--) {
      const bytes = new Uint32Array(1);
      crypto.getRandomValues(bytes);
      const j = bytes[0] % (i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  // ---------- DOM building helpers (no innerHTML — see header comment) ----------

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function svgIcon(path) {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("fill", "currentColor");
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", path);
    svg.appendChild(p);
    return svg;
  }

  const LOCK_PATH =
    "M5 8V6a5 5 0 0 1 10 0v2h1a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1h1Zm2 0h6V6a3 3 0 0 0-6 0v2Z";
  const REFRESH_PATH = "M10 2a8 8 0 1 0 8 8h-2a6 6 0 1 1-1.8-4.2L12 8h6V2l-2.3 2.3A7.96 7.96 0 0 0 10 2Z";
  const USER_PATH =
    "M10 10a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0 2c-4 0-8 2-8 5v1h16v-1c0-3-4-5-8-5Z";

  // ---------- field discovery ----------

  function isVisible(field) {
    if (!field.isConnected) return false;

    if (typeof field.checkVisibility === "function") {
      if (!field.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) {
        return false;
      }
    } else {
      const style = window.getComputedStyle(field);
      if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    }

    const rect = field.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return false;

    // `checkVisibility()` doesn't account for a clipping ancestor (e.g.
    // `overflow: hidden` on a zero-height wrapper) — a real-world pattern
    // for pre-rendering a later step's field: Apple's sign-in stacks a
    // `password` input directly under the visible email field, inside a
    // wrapper with `height: 0; overflow: hidden`, until you advance past
    // the email step. The field's own rect still reports real, non-zero
    // geometry, so the only way to tell it isn't actually on screen is to
    // hit-test its own center and check it's really what's on top there.
    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    if (cx < 0 || cy < 0 || cx > window.innerWidth || cy > window.innerHeight) return false;
    const hit = field.getRootNode().elementFromPoint(cx, cy);
    if (hit !== field) return false;

    return true;
  }

  function findPasswordFields(root = document) {
    return Array.from(root.querySelectorAll('input[type="password"]')).filter(isVisible);
  }

  function isUsernameLikeField(field) {
    if (!(field instanceof HTMLInputElement)) return false;
    if (field.type === "email") return true;
    // `autocomplete` can be a space-separated token list (e.g. Apple's
    // sign-in uses "username webauthn") — check membership, not equality.
    const tokens = (field.autocomplete || "").toLowerCase().split(/\s+/);
    return tokens.includes("username");
  }

  function findUsernameFieldFor(passwordField) {
    const form = passwordField.closest("form") || document;
    const keywords = ["user", "email", "login", "identifier", "account"];
    const candidates = Array.from(
      form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')
    ).filter(isVisible);

    const scored = candidates
      .map((input) => {
        const haystack = `${input.name} ${input.id} ${input.autocomplete} ${input.placeholder}`.toLowerCase();
        return { input, score: keywords.some((k) => haystack.includes(k)) ? 1 : 0 };
      })
      .filter((c) => c.score > 0);

    if (scored.length > 0) return scored[0].input;
    return candidates[0] || null;
  }

  /** All *other* visible password fields in the same form — i.e. "confirm password" siblings. */
  function findConfirmFields(passwordField) {
    const form = passwordField.closest("form") || document;
    return findPasswordFields(form).filter((f) => f !== passwordField);
  }

  function setValue(input, value) {
    const proto =
      input instanceof HTMLTextAreaElement ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /** Fills whichever of {username, password} fields exist near `field` — used
   *  both when a password-field marker is clicked and a username-field one. */
  function fillEntryFromField(field, entry) {
    const isPassword = field.type === "password";
    const passwordField = isPassword ? field : findPasswordFields()[0] || null;
    const usernameField = isPassword ? findUsernameFieldFor(field) : field;
    if (usernameField) setValue(usernameField, entry.username);
    if (passwordField) setValue(passwordField, entry.password);
  }

  function fillCredentials(username, password) {
    const passwordField = findPasswordFields()[0] || null;
    const usernameField = passwordField ? findUsernameFieldFor(passwordField) : null;

    let filled = false;
    if (usernameField && username) {
      setValue(usernameField, username);
      filled = true;
    }
    if (passwordField && password) {
      setValue(passwordField, password);
      filled = true;
    }
    return filled;
  }

  // Legacy message from popup.js's per-row "Fill" button.
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type !== "PASS_FILL_CREDENTIALS") return undefined;
    sendResponse({ filled: fillCredentials(message.username, message.password) });
    return false;
  });

  // ---------- shadow-DOM UI ----------

  function ensureShadowRoot() {
    if (shadowRoot) return shadowRoot;
    const host = document.createElement("div");
    host.id = "pass-extension-root";
    host.style.all = "initial";
    document.documentElement.appendChild(host);
    shadowRoot = host.attachShadow({ mode: "open" });

    // `textContent` (unlike innerHTML) is never blocked by Trusted Types.
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
      .marker {
        position: fixed;
        /* width/height/border-radius are set inline per field in
           positionMarker() — they depend on the field's own size so the
           icon never overflows a short field. */
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        background: #4f46e5;
        color: white;
        z-index: 2147483001;
        box-shadow: 0 1px 3px rgba(0,0,0,0.3);
      }
      .marker svg { width: 60%; height: 60%; }
      .dropdown {
        position: fixed;
        width: 280px;
        max-height: 320px;
        overflow-y: auto;
        background: #ffffff;
        color: #16181d;
        border-radius: 10px;
        box-shadow: 0 8px 24px rgba(16,24,40,0.2), 0 0 0 1px rgba(16,24,40,0.06);
        z-index: 2147483002;
        font-size: 13px;
        padding: 6px;
      }
      .dropdown-section-label {
        font-size: 10.5px;
        font-weight: 700;
        color: #6b7280;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        padding: 6px 8px 4px;
      }
      .dropdown-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px;
        border-radius: 8px;
        cursor: pointer;
      }
      .dropdown-item:hover { background: #f0f1f6; }
      .dropdown-avatar {
        width: 26px; height: 26px; border-radius: 7px;
        display: flex; align-items: center; justify-content: center;
        background: #eef0fe; color: #4f46e5; font-weight: 700; font-size: 12px;
        flex-shrink: 0; text-transform: uppercase;
      }
      .dropdown-avatar svg { width: 14px; height: 14px; }
      .dropdown-item-text { flex: 1; min-width: 0; }
      .dropdown-item-title { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .dropdown-item-sub { color: #6b7280; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .dropdown-item-sub.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
      .dropdown-empty { padding: 10px 8px; color: #6b7280; font-size: 12px; }
      .dropdown-divider { height: 1px; background: #e5e7eb; margin: 4px 0; }
      .regen-btn {
        width: 22px; height: 22px; border-radius: 6px; border: none; background: transparent;
        color: #6b7280; display: flex; align-items: center; justify-content: center; cursor: pointer; flex-shrink: 0;
      }
      .regen-btn:hover { background: #e5e7eb; color: #16181d; }
      .regen-btn svg { width: 14px; height: 14px; }

      .toast {
        position: fixed;
        top: 16px;
        right: 16px;
        width: 300px;
        background: #ffffff;
        color: #16181d;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(16,24,40,0.25), 0 0 0 1px rgba(16,24,40,0.06);
        z-index: 2147483003;
        padding: 14px;
      }
      .toast-title { font-weight: 700; font-size: 13.5px; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }
      .toast-title svg { width: 15px; height: 15px; flex-shrink: 0; }
      .toast-body { font-size: 12.5px; color: #6b7280; margin-bottom: 10px; }
      .toast-actions { display: flex; gap: 8px; justify-content: flex-end; }
      .toast-btn { padding: 6px 12px; border-radius: 7px; border: none; font-size: 12px; font-weight: 600; cursor: pointer; }
      .toast-btn-primary { background: #4f46e5; color: white; }
      .toast-btn-primary:hover { background: #4338ca; }
      .toast-btn-secondary { background: #f0f1f6; color: #16181d; }
      .toast-btn-secondary:hover { background: #e5e7eb; }
    `;
    shadowRoot.appendChild(style);
    return shadowRoot;
  }

  // ---------- markers (one per password/username field) ----------

  const MARKER_INSET = 6; // gap kept from the field's own right/top/bottom edges
  const MARKER_MAX_SIZE = 20;
  const MARKER_MIN_SIZE = 14;

  function positionMarker(field, marker) {
    const rect = field.getBoundingClientRect();
    // Shrink to fit short fields (never taller than the field itself minus
    // a small margin) instead of a fixed size that overflows them.
    const size = Math.max(MARKER_MIN_SIZE, Math.min(MARKER_MAX_SIZE, rect.height - MARKER_INSET * 2));
    marker.style.width = `${size}px`;
    marker.style.height = `${size}px`;
    marker.style.borderRadius = `${Math.max(4, Math.round(size / 4))}px`;
    marker.style.top = `${rect.top + (rect.height - size) / 2}px`;
    // Keep it inset from the right edge rather than flush against it, and
    // never past the field's own left edge on a very narrow field.
    marker.style.left = `${Math.max(rect.left, rect.right - size - MARKER_INSET)}px`;
  }

  function attachMarker(field, kind) {
    if (PROCESSED.has(field)) return;
    PROCESSED.add(field);

    const root = ensureShadowRoot();
    const marker = el("div", "marker");
    marker.appendChild(svgIcon(kind === "password" ? LOCK_PATH : USER_PATH));
    marker.title = "Pass";
    root.appendChild(marker);
    markers.set(field, marker);
    positionMarker(field, marker);

    marker.addEventListener("mousedown", (e) => {
      e.preventDefault(); // don't steal focus away from the field
      e.stopPropagation();
      openDropdownFor(field, kind);
    });

    field.addEventListener("focus", () => openDropdownFor(field, kind));
    field.addEventListener("blur", () => {
      // Allow a dropdown-item mousedown (which fires before blur) to
      // finish its own handling; only hide the marker's dropdown here if
      // focus didn't move into it.
      setTimeout(() => {
        if (dropdownEl && !dropdownEl.matches(":hover")) closeDropdown();
      }, 120);
    });

    if (kind === "password") {
      field.addEventListener("input", () => {
        if (dropdownEl && dropdownEl.dataset.forField === fieldKey(field)) {
          openDropdownFor(field, kind); // refresh (suggestion row appears/disappears as field empties)
        }
      });
    }
  }

  let fieldKeyCounter = 0;
  const fieldKeys = new WeakMap();
  function fieldKey(field) {
    if (!fieldKeys.has(field)) fieldKeys.set(field, String(++fieldKeyCounter));
    return fieldKeys.get(field);
  }

  function repositionAll() {
    for (const [field, marker] of markers) {
      if (!field.isConnected) {
        marker.remove();
        markers.delete(field);
        continue;
      }
      positionMarker(field, marker);
    }
    if (dropdownEl && dropdownEl.dataset.forField) {
      const field = [...markers.keys()].find((f) => fieldKey(f) === dropdownEl.dataset.forField);
      if (field) positionDropdown(field, dropdownEl);
    }
  }

  window.addEventListener("scroll", () => requestReposition(), true);
  window.addEventListener("resize", () => requestReposition());
  function requestReposition() {
    if (markerPositionsDirty) return;
    markerPositionsDirty = true;
    requestAnimationFrame(() => {
      markerPositionsDirty = false;
      repositionAll();
    });
  }
  setInterval(repositionAll, 500); // cheap fallback for layout shifts scroll/resize don't catch

  // ---------- dropdown ----------

  function positionDropdown(field, dropdown) {
    const rect = field.getBoundingClientRect();
    const top = rect.bottom + 6;
    let left = rect.left;
    const maxLeft = window.innerWidth - 280 - 8;
    if (left > maxLeft) left = Math.max(8, maxLeft);
    dropdown.style.top = `${top}px`;
    dropdown.style.left = `${left}px`;
  }

  function closeDropdown() {
    if (dropdownEl) {
      dropdownEl.remove();
      dropdownEl = null;
    }
  }

  function setDropdownMessage(dropdown, text) {
    dropdown.replaceChildren(el("div", "dropdown-empty", text));
  }

  async function openDropdownFor(field, kind) {
    closeDropdown();
    const root = ensureShadowRoot();

    const dropdown = el("div", "dropdown");
    dropdown.dataset.forField = fieldKey(field);
    setDropdownMessage(dropdown, "Loading…");
    root.appendChild(dropdown);
    positionDropdown(field, dropdown);
    dropdownEl = dropdown;

    let matches = [];
    let isUnlocked = false;
    try {
      const res = await sendToBackground("PASS_GET_MATCHES_FOR_DOMAIN", { hostname: location.hostname });
      matches = res.matches || [];
      isUnlocked = res.isUnlocked;
    } catch {
      // background/native host unreachable — still allow password suggestion below.
    }

    if (dropdownEl !== dropdown) return; // superseded by a newer call

    renderDropdown(dropdown, field, kind, matches, isUnlocked);
  }

  function renderDropdown(dropdown, field, kind, matches, isUnlocked) {
    dropdown.replaceChildren();

    if (matches.length > 0) {
      dropdown.appendChild(el("div", "dropdown-section-label", t("content_saved_in_pass")));

      for (const entry of matches) {
        const avatar = el("div", "dropdown-avatar", (entry.website || "?").charAt(0));
        const title = el("div", "dropdown-item-title", entry.website);
        const sub = el("div", "dropdown-item-sub", entry.username);
        const text = el("div", "dropdown-item-text");
        text.append(title, sub);

        const item = el("div", "dropdown-item");
        item.append(avatar, text);
        item.addEventListener("mousedown", async (e) => {
          e.preventDefault();
          // Close first: fillEntryFromField looks up the username/password
          // fields via the same visibility hit-test as scanning, which
          // would otherwise see our own still-open dropdown sitting on top
          // of a field it needs to check (e.g. the confirm-password field
          // right under a signup form's password field).
          closeDropdown();
          try {
            const full = await sendToBackground("PASS_GET_ENTRY", { id: entry.id });
            fillEntryFromField(field, full);
          } catch {
            /* nothing more to do from the page if this fails */
          }
        });
        dropdown.appendChild(item);
      }
    } else if (!isUnlocked) {
      dropdown.appendChild(
        el("div", "dropdown-empty", t("content_unlock_hint"))
      );
    }

    if (kind === "password" && field.value === "") {
      if (matches.length > 0) dropdown.appendChild(el("div", "dropdown-divider"));
      dropdown.appendChild(renderSuggestionRow(field));
    }

    if (dropdown.children.length === 0) {
      setDropdownMessage(dropdown, t("content_no_saved_logins"));
    }
  }

  function renderSuggestionRow(field) {
    const wrap = document.createDocumentFragment();
    wrap.appendChild(el("div", "dropdown-section-label", t("content_suggested_password")));

    let candidate = generatePassword();

    const avatar = el("div", "dropdown-avatar");
    avatar.style.background = "#eef0fe";
    avatar.appendChild(svgIcon(LOCK_PATH));

    const title = el("div", "dropdown-item-title", t("content_use_suggested_password"));
    const sub = el("div", "dropdown-item-sub mono", candidate);
    const text = el("div", "dropdown-item-text");
    text.append(title, sub);

    const regen = el("button", "regen-btn");
    regen.type = "button";
    regen.title = "Generate another";
    regen.appendChild(svgIcon(REFRESH_PATH));
    regen.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      candidate = generatePassword();
      sub.textContent = candidate;
    });

    const row = el("div", "dropdown-item");
    row.append(avatar, text, regen);
    row.addEventListener("mousedown", (e) => {
      e.preventDefault();
      // Close first — see the matching comment on the "Saved in Pass"
      // item handler above.
      closeDropdown();
      setValue(field, candidate);
      for (const confirmField of findConfirmFields(field)) {
        setValue(confirmField, candidate);
      }
    });

    wrap.appendChild(row);
    return wrap;
  }

  document.addEventListener(
    "mousedown",
    (e) => {
      if (!dropdownEl) return;
      const path = e.composedPath();
      if (path.includes(dropdownEl)) return;
      if ([...markers.values()].some((m) => path.includes(m))) return;
      closeDropdown();
    },
    true
  );

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDropdown();
  });

  // ---------- scanning for fields (initial + dynamic) ----------

  function scan(root = document) {
    const claimedUsernameFields = new Set();
    const passwordFields = findPasswordFields(root);
    for (const field of passwordFields) {
      attachMarker(field, "password");
      const paired = findUsernameFieldFor(field);
      if (paired) claimedUsernameFields.add(paired);
    }

    // Standalone username/email fields not already paired with a password
    // field on this page — covers split login flows (email step, then a
    // separate password step) like Google's.
    const usernameFields = Array.from(root.querySelectorAll("input")).filter(
      (f) => isUsernameLikeField(f) && isVisible(f) && !claimedUsernameFields.has(f)
    );
    for (const field of usernameFields) attachMarker(field, "username");
  }

  scan();
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.querySelectorAll) scan(node);
        if (node.matches?.('input[type="password"]')) attachMarker(node, "password");
        else if (node.matches?.("input") && isUsernameLikeField(node)) attachMarker(node, "username");
      }
    }
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });

  // A field that already existed but was transiently covered (e.g. by a
  // loading spinner during SPA hydration) at scan-time fails the
  // hit-test in `isVisible` and is never revisited — it isn't a *new*
  // node, so the observer above never rescans it once the spinner goes
  // away. Re-scanning the whole document a few times shortly after load
  // self-heals that, since `attachMarker`'s own PROCESSED guard makes
  // repeat scans a no-op for anything already attached.
  for (const delay of [500, 1500, 3000]) {
    setTimeout(() => scan(), delay);
  }

  // ---------- save/update detection ----------

  let saveToastShown = false;

  async function maybeOfferSave(passwordField) {
    if (saveToastShown) return;
    const usernameField = findUsernameFieldFor(passwordField);
    const password = passwordField.value;
    const username = usernameField ? usernameField.value : "";
    if (!password || !username) return;

    let offer;
    try {
      // hostname/url are this *frame's* own — for a cross-origin sign-in
      // iframe (Apple/Google/Okta-style) that's the wrong site identity,
      // so background.js overrides them with the tab's actual top-level
      // URL before matching, and returns the corrected website/url/id
      // inside `offer` itself. Use that, not anything computed here.
      const res = await sendToBackground("PASS_OFFER_SAVE_CREDENTIALS", {
        hostname: location.hostname,
        url: location.href,
        username,
        password,
      });
      offer = res.offer;
    } catch {
      return; // e.g. locked / native host unavailable — fail silently on the page
    }
    if (!offer) return;

    showSaveToast(offer);
  }

  function showSaveToast(offer) {
    saveToastShown = true;
    const root = ensureShadowRoot();
    const isUpdate = offer.action === "update";

    const title = el("div", "toast-title");
    title.appendChild(svgIcon(LOCK_PATH));
    title.appendChild(document.createTextNode(t(isUpdate ? "content_update_title" : "content_save_title")));

    const body = el(
      "div",
      "toast-body",
      isUpdate
        ? t("content_update_body", [offer.username, offer.website])
        : t("content_save_body", [offer.username, offer.website])
    );

    const dismissBtn = el("button", "toast-btn toast-btn-secondary", t("content_not_now"));
    dismissBtn.type = "button";
    const saveBtn = el("button", "toast-btn toast-btn-primary", t(isUpdate ? "content_update" : "content_save"));
    saveBtn.type = "button";
    const actions = el("div", "toast-actions");
    actions.append(dismissBtn, saveBtn);

    const toast = el("div", "toast");
    toast.append(title, body, actions);

    const dismissToast = () => {
      toast.remove();
      saveToastShown = false; // allow a later submit attempt to offer again
    };

    dismissBtn.addEventListener("click", dismissToast);
    saveBtn.addEventListener("click", async () => {
      try {
        if (isUpdate) {
          await sendToBackground("PASS_UPDATE_ENTRY", {
            id: offer.id,
            website: offer.website,
            username: offer.username,
            url: offer.url,
            password: offer.password,
          });
        } else {
          await sendToBackground("PASS_ADD_ENTRY", {
            website: offer.website,
            url: offer.url,
            username: offer.username,
            password: offer.password,
          });
        }
      } catch {
        /* nothing more to do from the page if this fails */
      }
      dismissToast();
    });

    root.appendChild(toast);
    setTimeout(dismissToast, 15000);
  }

  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target;
      if (!(form instanceof HTMLFormElement)) return;
      const passwordField = findPasswordFields(form)[0];
      if (passwordField) maybeOfferSave(passwordField);
    },
    true
  );

  // Many modern sites don't use a real <form> submit (SPA + fetch/XHR), so
  // also treat "Enter" inside a tracked password field, or a click on
  // anything that looks like a submit button, as a submission signal.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter") return;
      const field = e.target;
      if (field instanceof HTMLInputElement && field.type === "password") {
        maybeOfferSave(field);
      }
    },
    true
  );

  document.addEventListener(
    "click",
    (e) => {
      const target = e.target.closest?.('button, input[type="submit"], [role="button"]');
      if (!target) return;
      const text = `${target.textContent} ${target.value || ""} ${target.getAttribute("aria-label") || ""}`.toLowerCase();
      if (!/(log ?in|sign ?in|sign ?up|register|create account|continue|submit)/.test(text)) return;
      const passwordField = findPasswordFields()[0];
      if (passwordField) setTimeout(() => maybeOfferSave(passwordField), 50);
    },
    true
  );
})();
