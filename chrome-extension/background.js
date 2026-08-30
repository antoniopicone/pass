// Background service worker: the single owner of the "unlocked vault"
// session and the only place that talks to the native messaging host.
// Content scripts can't call chrome.runtime.sendNativeMessage themselves,
// so both popup.js and content.js talk to *this* file over
// chrome.runtime.sendMessage, and this file is the one that calls the
// native host and keeps the master password in memory.
//
// The service worker can be killed by Chrome after ~30s idle (Manifest V3
// lifecycle), so the session is mirrored to chrome.storage.session (wiped
// when the browser closes) and rehydrated on every wake-up.

const NATIVE_HOST = "com.antoniopicone.pass_native_host";
const SESSION_TTL_MS = 5 * 60 * 1000; // re-prompt for the master password after 5 minutes idle

/** @type {{ vaultPath: string, masterPassword: string, unlockedAt: number, entries: any[] } | null} */
let session = null;
let sessionLoaded = false;
let sessionLoadPromise = null;

function ensureSessionLoaded() {
  if (sessionLoaded) return Promise.resolve();
  if (!sessionLoadPromise) {
    sessionLoadPromise = chrome.storage.session.get("passSession").then((stored) => {
      if (stored.passSession && Date.now() - stored.passSession.unlockedAt < SESSION_TTL_MS) {
        session = stored.passSession;
      }
      sessionLoaded = true;
    });
  }
  return sessionLoadPromise;
}

function persistSession() {
  if (session) {
    return chrome.storage.session.set({ passSession: session });
  }
  return chrome.storage.session.remove("passSession");
}

function sendNative(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(`${chrome.runtime.lastError.message} (is the native host installed?)`));
        return;
      }
      if (!response) {
        reject(new Error("No response from native host."));
        return;
      }
      if (!response.ok) {
        reject(new Error(response.error || "Unknown error."));
        return;
      }
      resolve(response);
    });
  });
}

function isSessionValid() {
  return !!session && Date.now() - session.unlockedAt < SESSION_TTL_MS;
}

async function refreshEntries() {
  const res = await sendNative({
    cmd: "unlockVault",
    vaultPath: session.vaultPath,
    masterPassword: session.masterPassword,
  });
  session.entries = res.entries || [];
  session.unlockedAt = Date.now();
  await persistSession();
  return session.entries;
}

/** Public state shape handed to popup.js / content.js — never includes the master password. */
function publicState() {
  if (!isSessionValid()) return { isUnlocked: false };
  return {
    isUnlocked: true,
    vaultPath: session.vaultPath,
    entries: session.entries,
  };
}

/** Entries whose website/url/additionalUrls look like they belong to `hostname`. */
function matchesForHostname(hostname) {
  if (!isSessionValid() || !hostname) return [];
  const needle = hostname.toLowerCase();
  return session.entries.filter((e) => {
    const website = (e.website || "").toLowerCase();
    const urls = [e.url, ...(e.additionalUrls || [])];
    return (
      urls.some((u) => (u || "").toLowerCase().includes(needle)) ||
      needle.includes(website) ||
      website.includes(needle)
    );
  });
}

function guessWebsiteName(hostname) {
  const host = (hostname || "").replace(/^www\./, "");
  const label = host.split(".")[0] || host;
  return label.charAt(0).toUpperCase() + label.slice(1);
}

const handlers = {
  async PASS_GET_STATE() {
    return publicState();
  },

  async PASS_UNLOCK({ vaultPath, masterPassword }) {
    const res = await sendNative({ cmd: "unlockVault", vaultPath, masterPassword });
    session = { vaultPath, masterPassword, unlockedAt: Date.now(), entries: res.entries || [] };
    await persistSession();
    return publicState();
  },

  async PASS_INIT_VAULT({ vaultPath, masterPassword }) {
    await sendNative({ cmd: "initVault", vaultPath, masterPassword });
    return handlers.PASS_UNLOCK({ vaultPath, masterPassword });
  },

  async PASS_LOCK() {
    session = null;
    await persistSession();
    return { isUnlocked: false };
  },

  async PASS_REFRESH() {
    if (!isSessionValid()) return publicState();
    await refreshEntries();
    return publicState();
  },

  async PASS_GET_ENTRY({ id }) {
    if (!isSessionValid()) throw new Error("Locked.");
    const res = await sendNative({
      cmd: "getEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    session.unlockedAt = Date.now();
    await persistSession();
    return res.entry;
  },

  async PASS_ADD_ENTRY({ website, url, username, password, notes, additionalUrls }) {
    if (!isSessionValid()) throw new Error("Locked.");
    const res = await sendNative({
      cmd: "addEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      website,
      url,
      username,
      entryPassword: password,
      notes: notes || "",
      additionalUrls: additionalUrls || [],
    });
    await refreshEntries();
    return { id: res.id, entries: session.entries };
  },

  async PASS_UPDATE_ENTRY({ id, website, url, username, password, notes, additionalUrls }) {
    if (!isSessionValid()) throw new Error("Locked.");
    const req = {
      cmd: "updateEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
      website,
      url,
      username,
    };
    // The native host only overwrites a field when its key is present at
    // all — omit password/notes/additionalUrls entirely for "leave
    // unchanged" rather than sending an empty value (which would blank it
    // out). website/url/username are always resent, matching the existing
    // full-replace contract for those three.
    if (password) req.entryPassword = password;
    if (notes !== undefined) req.notes = notes;
    if (additionalUrls !== undefined) req.additionalUrls = additionalUrls;
    await sendNative(req);
    await refreshEntries();
    return { entries: session.entries };
  },

  async PASS_GET_ENTRY_HISTORY({ id }) {
    if (!isSessionValid()) throw new Error("Locked.");
    const res = await sendNative({
      cmd: "getEntryHistory",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    return { history: res.history || [] };
  },

  async PASS_DELETE_ENTRY({ id }) {
    if (!isSessionValid()) throw new Error("Locked.");
    await sendNative({
      cmd: "deleteEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    await refreshEntries();
    return { entries: session.entries };
  },

  async PASS_ADD_TOTP({ id, uri }) {
    if (!isSessionValid()) throw new Error("Locked.");
    await sendNative({
      cmd: "addTotpUri",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
      uri,
    });
    await refreshEntries();
    return { entries: session.entries };
  },

  async PASS_REMOVE_TOTP({ id }) {
    if (!isSessionValid()) throw new Error("Locked.");
    await sendNative({
      cmd: "removeTotp",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    await refreshEntries();
    return { entries: session.entries };
  },

  async PASS_MERGE({ otherPath }) {
    if (!isSessionValid()) throw new Error("Locked.");
    const res = await sendNative({
      cmd: "mergeFromFile",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      otherPath,
    });
    await refreshEntries();
    return {
      created: res.created,
      updated: res.updated,
      unchanged: res.unchanged,
      deleted: res.deleted,
      entries: session.entries,
    };
  },

  // --- Content-script-facing (autofill + save prompt) ---

  async PASS_GET_MATCHES_FOR_DOMAIN({ hostname }) {
    if (!isSessionValid()) return { isUnlocked: false, matches: [] };
    return { isUnlocked: true, matches: matchesForHostname(hostname) };
  },

  /**
   * Called by content.js right after it sees a login/signup form submitted
   * with a non-empty username+password. Decides whether the page should
   * show a "Save password?" / "Update password?" banner. Deliberately does
   * nothing if the vault isn't already unlocked in this browsing session —
   * prompting a random webpage's injected banner for the master password
   * would look indistinguishable from phishing, so saving only works while
   * the popup has already been unlocked once.
   *
   * The returned `offer` carries its own `website`/`url` (derived from
   * `hostname`, which by the time this runs has already been corrected to
   * the tab's top-level site — see the onMessage listener below) rather
   * than trusting whatever content.js guessed, so the eventual save/update
   * always uses the right identity even when content.js itself is running
   * inside a cross-origin sign-in iframe (Apple/Google/Okta-style).
   */
  async PASS_OFFER_SAVE_CREDENTIALS({ hostname, url, username, password }) {
    if (!isSessionValid() || !username || !password) return { offer: null };
    const website = guessWebsiteName(hostname);

    const existing = matchesForHostname(hostname).find(
      (e) => e.username.toLowerCase() === username.toLowerCase()
    );

    if (!existing) {
      return { offer: { action: "create", website, url, username, password } };
    }

    // Need the real (decrypted) password to know if it actually changed.
    const full = await handlers.PASS_GET_ENTRY({ id: existing.id });
    if (full.password === password) {
      return { offer: null }; // already saved verbatim
    }
    return {
      offer: { action: "update", id: existing.id, website: existing.website, url, username, password },
    };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handler = message && handlers[message.type];
  if (!handler) return false;

  const payload = { ...(message.payload || {}) };

  // Content scripts running in a cross-origin sub-frame — the common
  // pattern for identity-provider sign-in flows, e.g. Apple's
  // account.apple.com embeds its actual auth form from idmsa.apple.com,
  // Google/Okta do the same on their own subdomains — see their *own*
  // frame's hostname/URL via `location`, which is the wrong identity for
  // matching or saving credentials: what matters is the site the user
  // thinks they're on, i.e. the tab's top-level URL. `sender.tab.url`
  // reflects that regardless of which frame within the tab sent the
  // message, so it overrides whatever hostname/url content.js guessed.
  if (sender.tab && sender.tab.url && "hostname" in payload) {
    try {
      payload.hostname = new URL(sender.tab.url).hostname;
      payload.url = sender.tab.url;
    } catch {
      /* keep content.js's own values */
    }
  }

  ensureSessionLoaded()
    .then(() => handler(payload))
    .then((result) => sendResponse({ ok: true, result }))
    .catch((error) => sendResponse({ ok: false, error: error.message || String(error) }));

  return true; // keep the message channel open for the async response
});
