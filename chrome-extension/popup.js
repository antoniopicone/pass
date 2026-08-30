// Thin UI layer: all vault access goes through the background service
// worker (background.js), which is the only place holding the master
// password and talking to the native messaging host. This lets the same
// unlocked session be shared with content.js (in-page autofill/save
// prompts), which can't call native messaging directly.

const VIEW_IDS = ["locked-view", "list-view", "merge-view", "add-view", "detail-view"];

const ICON_EYE_SVG =
  '<svg class="icon" viewBox="0 0 20 20"><path fill="currentColor" d="M10 4C5 4 1.7 8 1.7 8s3.3 4 8.3 4 8.3-4 8.3-4-3.3-4-8.3-4Zm0 6.5A2.5 2.5 0 1 1 10 5.5a2.5 2.5 0 0 1 0 5Z"/></svg>';
const ICON_COPY_SVG =
  '<svg class="icon" viewBox="0 0 20 20"><path fill="currentColor" d="M6 2h9v11H6V2Zm-3 3h2v11h9v2H3V5Z"/></svg>';

// ---------- i18n (chrome.i18n + _locales/<lang>/messages.json) ----------

function t(key, substitutions) {
  return chrome.i18n.getMessage(key, substitutions) || key;
}

/** Applies data-i18n / data-i18n-placeholder / data-i18n-title attributes
 *  found in the static HTML. For an element with both a leading text node
 *  and nested elements (e.g. a field label with a hint span inside it),
 *  only that leading text node is replaced — the nested element carries
 *  its own data-i18n and is handled by its own pass through this loop. */
function applyI18n(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((el) => {
    const msg = t(el.getAttribute("data-i18n"));
    if (!msg) return;
    const hasElementChildren = [...el.childNodes].some((n) => n.nodeType === Node.ELEMENT_NODE);
    if (!hasElementChildren) {
      el.textContent = msg;
      return;
    }
    const firstNode = el.childNodes[0];
    if (firstNode && firstNode.nodeType === Node.TEXT_NODE) {
      firstNode.textContent = `${msg} `;
    } else {
      el.insertBefore(document.createTextNode(`${msg} `), el.firstChild);
    }
  });
  root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    el.placeholder = t(el.getAttribute("data-i18n-placeholder"));
  });
  root.querySelectorAll("[data-i18n-title]").forEach((el) => {
    el.title = t(el.getAttribute("data-i18n-title"));
  });
}

applyI18n();

const els = {
  vaultPath: document.getElementById("vault-path"),
  masterPassword: document.getElementById("master-password"),
  unlockBtn: document.getElementById("unlock-btn"),
  initBtn: document.getElementById("init-btn"),
  lockBtn: document.getElementById("lock-btn"),
  status: document.getElementById("status"),
  search: document.getElementById("search"),
  entryList: document.getElementById("entry-list"),
  fabAdd: document.getElementById("fab-add"),

  showMergeBtn: document.getElementById("show-merge-btn"),
  mergeBackBtn: document.getElementById("merge-back-btn"),
  mergePath: document.getElementById("merge-path"),
  mergeBtn: document.getElementById("merge-btn"),

  addBackBtn: document.getElementById("add-back-btn"),
  addWebsite: document.getElementById("add-website"),
  addUrl: document.getElementById("add-url"),
  addUsername: document.getElementById("add-username"),
  addPassword: document.getElementById("add-password"),
  addRevealBtn: document.getElementById("add-reveal-btn"),
  addGenerateBtn: document.getElementById("add-generate-btn"),
  addAdditionalUrls: document.getElementById("add-additional-urls"),
  addNotes: document.getElementById("add-notes"),
  addSaveBtn: document.getElementById("add-save-btn"),

  detailBackBtn: document.getElementById("detail-back-btn"),
  detailEditBtn: document.getElementById("detail-edit-btn"),
  detailDeleteBtn: document.getElementById("detail-delete-btn"),
  detailAvatar: document.getElementById("detail-avatar"),
  detailWebsite: document.getElementById("detail-website"),
  detailUsernameSub: document.getElementById("detail-username-sub"),
  detailViewFields: document.getElementById("detail-view-fields"),
  detailUsername: document.getElementById("detail-username"),
  detailPassword: document.getElementById("detail-password"),
  detailRevealBtn: document.getElementById("detail-reveal-btn"),
  detailUrl: document.getElementById("detail-url"),
  detailAdditionalUrlsRow: document.getElementById("detail-additional-urls-row"),
  detailAdditionalUrls: document.getElementById("detail-additional-urls"),
  detailNotesRow: document.getElementById("detail-notes-row"),
  detailNotes: document.getElementById("detail-notes"),
  detailTotpCode: document.getElementById("detail-totp-code"),
  detailTotpActionBtn: document.getElementById("detail-totp-action-btn"),
  detailMeta: document.getElementById("detail-meta"),
  detailHistoryCard: document.getElementById("detail-history-card"),
  detailHistoryToggle: document.getElementById("detail-history-toggle"),
  detailHistorySummary: document.getElementById("detail-history-summary"),
  detailHistoryChevron: document.getElementById("detail-history-chevron"),
  detailHistoryList: document.getElementById("detail-history-list"),

  detailEditFields: document.getElementById("detail-edit-fields"),
  editWebsite: document.getElementById("edit-website"),
  editUrl: document.getElementById("edit-url"),
  editUsername: document.getElementById("edit-username"),
  editPassword: document.getElementById("edit-password"),
  editGenerateBtn: document.getElementById("edit-generate-btn"),
  editAdditionalUrls: document.getElementById("edit-additional-urls"),
  editNotes: document.getElementById("edit-notes"),
  editCancelBtn: document.getElementById("edit-cancel-btn"),
  editSaveBtn: document.getElementById("edit-save-btn"),
};

let state = { isUnlocked: false, entries: [] };
let currentDomain = "";
let selectedEntry = null; // full entry (with password), fetched on open
let totpTimer = null;

init();

async function init() {
  currentDomain = await getActiveTabDomain();
  try {
    state = await sendToBackground("PASS_GET_STATE");
  } catch {
    state = { isUnlocked: false, entries: [] };
  }

  if (state.isUnlocked) {
    els.vaultPath.value = state.vaultPath;
    showList();
  } else {
    els.vaultPath.value = "passwords.kdbx";
    showView("locked-view");
  }
}

function showView(id) {
  for (const v of VIEW_IDS) {
    document.getElementById(v).hidden = v !== id;
  }
  if (id !== "detail-view" && totpTimer) {
    clearInterval(totpTimer);
    totpTimer = null;
  }
}

function showList() {
  showView("list-view");
  renderList();
}

function sendToBackground(type, payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || !response.ok) {
        reject(new Error((response && response.error) || t("status_unknown_error")));
        return;
      }
      resolve(response.result);
    });
  });
}

async function getActiveTabDomain() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return "";
  try {
    return new URL(tab.url).hostname;
  } catch {
    return "";
  }
}

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}

function parseUrlsTextarea(text) {
  return text
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
}

// ---------- Password generation (Web Crypto, not Math.random) ----------

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

const AVATAR_COLORS = ["#4f46e5", "#0ea5e9", "#12b76a", "#f59e0b", "#e5484d", "#a855f7", "#0891b2", "#db2777"];

function colorForName(name) {
  const str = name || "?";
  let hash = 0;
  for (let i = 0; i < str.length; i++) hash = (hash * 31 + str.charCodeAt(i)) >>> 0;
  return AVATAR_COLORS[hash % AVATAR_COLORS.length];
}

function entryUrls(entry) {
  return [entry.url, ...(entry.additionalUrls || [])].filter(Boolean);
}

function isDomainMatch(entry) {
  if (!currentDomain) return false;
  const needle = currentDomain.toLowerCase();
  return entryUrls(entry).some((u) => u.toLowerCase().includes(needle));
}

// A small set of common two-part public suffixes, for a "good enough"
// registrable-domain heuristic without shipping a full public suffix list —
// e.g. so a favicon request for "idmsa.apple.com" or "www.bbc.co.uk" uses
// "apple.com" / "bbc.co.uk", not the exact subdomain.
const TWO_PART_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
  "co.jp", "ne.jp", "or.jp", "ac.jp",
  "co.nz", "org.nz", "govt.nz",
  "co.za", "org.za",
  "co.in", "net.in", "org.in",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "com.br", "net.br", "org.br",
  "com.mx", "com.tr", "com.sg", "com.hk", "com.tw",
  "co.kr", "co.il", "co.id", "co.th",
  "com.cn", "com.ar", "com.co", "com.pe",
]);

function registrableDomain(hostname) {
  const parts = hostname.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  const take = TWO_PART_SUFFIXES.has(lastTwo) ? 3 : 2;
  return parts.slice(-take).join(".");
}

// Uses the "favicon" permission's chrome-extension://<id>/_favicon/ endpoint
// — reads Chrome's own favicon cache (no network fetch of our own, no CORS
// concerns) — for the *registrable* domain (e.g. apple.com rather than
// idmsa.apple.com), since that's normally where the site's real favicon is
// actually registered/cached, and it's what makes an Apple/Google/Okta-style
// entry with several subdomains show one consistent icon. Falls back to
// Chrome's generic icon for a domain never visited in this browser, which
// is an acceptable, expected degrade.
function faviconUrl(pageUrl, size = 64) {
  if (!pageUrl) return null;
  try {
    const parsed = new URL(pageUrl);
    const domain = registrableDomain(parsed.hostname);
    const url = new URL(chrome.runtime.getURL("/_favicon/"));
    url.searchParams.set("pageUrl", `https://${domain}`);
    url.searchParams.set("size", String(size));
    return url.toString();
  } catch {
    return null;
  }
}

/** Fills an existing avatar element: the site's real favicon when it loads,
 *  the usual colored-letter placeholder otherwise (and until it does). */
function populateAvatar(avatar, entry) {
  avatar.replaceChildren();
  avatar.style.background = colorForName(entry.website);
  avatar.style.color = "#fff";

  // A separate text node (not `avatar.textContent`) so the "loaded" handler
  // below can remove just the letter — `avatar.textContent = ""` would
  // wipe out the <img> too, since textContent clears *all* children.
  const letter = document.createTextNode((entry.website || "?").charAt(0));
  avatar.appendChild(letter);

  const src = faviconUrl(entry.url);
  if (src) {
    const img = document.createElement("img");
    img.className = "avatar-favicon";
    img.alt = "";
    img.addEventListener("error", () => img.remove());
    img.addEventListener("load", () => {
      letter.remove();
      avatar.style.background = "transparent";
    });
    img.src = src;
    avatar.appendChild(img);
  }
}

/** A new avatar element (for list rows) — see `populateAvatar`. */
function buildAvatar(entry, extraClassName) {
  const avatar = document.createElement("div");
  avatar.className = extraClassName ? `avatar ${extraClassName}` : "avatar";
  populateAvatar(avatar, entry);
  return avatar;
}

// ---------- Locked view ----------

els.unlockBtn.addEventListener("click", async () => {
  const vaultPath = els.vaultPath.value.trim();
  const masterPassword = els.masterPassword.value;
  if (!vaultPath || !masterPassword) {
    setStatus(t("status_vault_path_and_password_required"), true);
    return;
  }

  setStatus(t("status_unlocking"));
  try {
    state = await sendToBackground("PASS_UNLOCK", { vaultPath, masterPassword });
    els.masterPassword.value = "";
    setStatus("");
    showList();
  } catch (e) {
    setStatus(e.message, true);
  }
});

els.initBtn.addEventListener("click", async () => {
  const vaultPath = els.vaultPath.value.trim();
  const masterPassword = els.masterPassword.value;
  if (!vaultPath || !masterPassword) {
    setStatus(t("status_vault_path_and_password_required"), true);
    return;
  }
  if (masterPassword.length < 8) {
    setStatus(t("status_master_password_min_length"), true);
    return;
  }

  setStatus(t("status_creating_vault"));
  try {
    state = await sendToBackground("PASS_INIT_VAULT", { vaultPath, masterPassword });
    els.masterPassword.value = "";
    setStatus(t("status_vault_created"));
    showList();
  } catch (e) {
    setStatus(e.message, true);
  }
});

els.masterPassword.addEventListener("keydown", (e) => {
  if (e.key === "Enter") els.unlockBtn.click();
});

// ---------- List view ----------

els.lockBtn.addEventListener("click", async () => {
  await sendToBackground("PASS_LOCK");
  state = { isUnlocked: false, entries: [] };
  els.masterPassword.value = "";
  setStatus("");
  showView("locked-view");
});

els.search.addEventListener("input", renderList);

els.fabAdd.addEventListener("click", () => {
  els.addWebsite.value = "";
  els.addUrl.value = currentDomain ? `https://${currentDomain}` : "";
  els.addUsername.value = "";
  els.addPassword.value = "";
  els.addPassword.type = "password";
  els.addAdditionalUrls.value = "";
  els.addNotes.value = "";
  setStatus("");
  showView("add-view");
  els.addWebsite.focus();
});

function renderList() {
  const query = els.search.value.trim().toLowerCase();
  const matches = state.entries.filter(
    (e) =>
      !query ||
      e.website.toLowerCase().includes(query) ||
      e.username.toLowerCase().includes(query) ||
      entryUrls(e).some((u) => u.toLowerCase().includes(query))
  );

  matches.sort((a, b) => {
    const aMatch = isDomainMatch(a);
    const bMatch = isDomainMatch(b);
    if (aMatch !== bMatch) return aMatch ? -1 : 1;
    return a.website.localeCompare(b.website);
  });

  els.entryList.replaceChildren();

  if (matches.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = state.entries.length === 0 ? t("empty_no_entries") : t("empty_no_matches");
    els.entryList.appendChild(li);
    return;
  }

  for (const entry of matches) {
    els.entryList.appendChild(renderEntryRow(entry));
  }
}

function renderEntryRow(entry) {
  const li = document.createElement("li");
  li.className = "entry";
  li.addEventListener("click", () => openDetail(entry.id));

  const avatar = buildAvatar(entry);

  const info = document.createElement("div");
  info.className = "entry-info";
  const title = document.createElement("div");
  title.className = "title";
  title.textContent = entry.website + (entry.hasTotp ? " 🔐" : "");
  const subtitle = document.createElement("div");
  subtitle.className = "subtitle";
  subtitle.textContent = entry.username;
  info.append(title, subtitle);

  li.append(avatar, info);

  if (isDomainMatch(entry)) {
    const badge = document.createElement("span");
    badge.className = "entry-match-badge";
    badge.textContent = t("entry_match_badge");
    li.append(badge);
  }

  const actions = document.createElement("div");
  actions.className = "entry-quick-actions";
  const fillBtn = document.createElement("button");
  fillBtn.className = "icon-btn";
  fillBtn.title = t("action_fill");
  fillBtn.innerHTML =
    '<svg class="icon" viewBox="0 0 20 20"><path fill="currentColor" d="M4 4h9l3 3v9H4V4Zm2 2v8h8V8h-2V6H6Zm2 4h4v2H8v-2Z"/></svg>';
  fillBtn.addEventListener("click", (ev) => {
    ev.stopPropagation();
    fillActiveTab(entry.id);
  });
  actions.append(fillBtn);
  li.append(actions);

  return li;
}

// ---------- Add entry view ----------

els.addBackBtn.addEventListener("click", () => showList());

els.addRevealBtn.addEventListener("click", () => {
  els.addPassword.type = els.addPassword.type === "password" ? "text" : "password";
});

els.addGenerateBtn.addEventListener("click", () => {
  els.addPassword.value = generatePassword();
  els.addPassword.type = "text";
});

els.addSaveBtn.addEventListener("click", async () => {
  const website = els.addWebsite.value.trim();
  const url = els.addUrl.value.trim();
  const username = els.addUsername.value.trim();
  const password = els.addPassword.value;
  const additionalUrls = parseUrlsTextarea(els.addAdditionalUrls.value);
  const notes = els.addNotes.value.trim();

  if (!website || !username || !password) {
    setStatus(t("status_website_username_password_required"), true);
    return;
  }

  setStatus(t("status_saving"));
  try {
    const res = await sendToBackground("PASS_ADD_ENTRY", {
      website,
      url,
      username,
      password,
      additionalUrls,
      notes,
    });
    state.entries = res.entries;
    setStatus(t("status_entry_saved"));
    showList();
  } catch (e) {
    setStatus(e.message, true);
  }
});

// ---------- Merge view ----------

els.showMergeBtn.addEventListener("click", () => {
  els.mergePath.value = "";
  showView("merge-view");
});
els.mergeBackBtn.addEventListener("click", () => showList());

els.mergeBtn.addEventListener("click", async () => {
  const otherPath = els.mergePath.value.trim();
  if (!otherPath) return;

  setStatus(t("status_merging"));
  try {
    const res = await sendToBackground("PASS_MERGE", { otherPath });
    state.entries = res.entries;
    setStatus(t("status_merge_done", [String(res.created), String(res.updated), String(res.deleted)]));
    showList();
  } catch (e) {
    setStatus(e.message, true);
  }
});

// ---------- Detail view ----------

async function openDetail(id) {
  setStatus("");
  try {
    selectedEntry = await sendToBackground("PASS_GET_ENTRY", { id });
  } catch (e) {
    setStatus(e.message, true);
    return;
  }
  renderDetail();
  showView("detail-view");
  loadHistory(id);
}

function renderDetail() {
  const entry = selectedEntry;
  populateAvatar(els.detailAvatar, entry);
  els.detailWebsite.textContent = entry.website;
  els.detailUsernameSub.textContent = entry.username;

  els.detailUsername.textContent = entry.username;
  els.detailPassword.textContent = "•".repeat(10);
  els.detailPassword.dataset.revealed = "false";
  els.detailUrl.textContent = entry.url || "(no URL)";

  const additionalUrls = entry.additionalUrls || [];
  els.detailAdditionalUrlsRow.hidden = additionalUrls.length === 0;
  els.detailAdditionalUrls.textContent = additionalUrls.join(", ");

  els.detailNotesRow.hidden = !entry.notes;
  els.detailNotes.textContent = entry.notes || "";

  els.detailViewFields.hidden = false;
  els.detailEditFields.hidden = true;

  renderTotpSection();

  const created = entry.createdAt ? new Date(entry.createdAt).toLocaleDateString() : "";
  const updated = entry.updatedAt ? new Date(entry.updatedAt).toLocaleDateString() : "";
  els.detailMeta.textContent = t("detail_meta", [created, updated]);
}

function renderTotpSection() {
  if (totpTimer) {
    clearInterval(totpTimer);
    totpTimer = null;
  }

  if (selectedEntry.totp) {
    const update = () => {
      els.detailTotpCode.textContent = `${selectedEntry.totp.code} (${selectedEntry.totp.secondsRemaining}s)`;
    };
    update();
    els.detailTotpActionBtn.textContent = t("action_copy");
    els.detailTotpActionBtn.onclick = () => copyToClipboard(selectedEntry.totp.code, t("status_mfa_copied", [String(selectedEntry.totp.secondsRemaining)]));
    totpTimer = setInterval(async () => {
      try {
        selectedEntry = await sendToBackground("PASS_GET_ENTRY", { id: selectedEntry.id });
        update();
      } catch {
        clearInterval(totpTimer);
      }
    }, 1000);
  } else {
    els.detailTotpCode.textContent = t("mfa_not_configured");
    els.detailTotpActionBtn.textContent = t("action_add_mfa");
    els.detailTotpActionBtn.onclick = addTotp;
  }
}

// ---------- Password history ----------

async function loadHistory(id) {
  els.detailHistoryCard.hidden = true;
  try {
    const res = await sendToBackground("PASS_GET_ENTRY_HISTORY", { id });
    renderHistory(res.history || []);
  } catch {
    // Locked/unreachable mid-session — just leave the card hidden.
  }
}

function renderHistory(history) {
  if (history.length === 0) {
    els.detailHistoryCard.hidden = true;
    return;
  }
  els.detailHistoryCard.hidden = false;
  els.detailHistorySummary.textContent = t("history_count", [String(history.length)]);
  els.detailHistoryList.hidden = true;
  els.detailHistoryChevron.classList.remove("icon-chevron-open");
  els.detailHistoryList.replaceChildren();

  for (const h of history) {
    els.detailHistoryList.appendChild(renderHistoryRow(h));
  }
}

function renderHistoryRow(historyEntry) {
  const li = document.createElement("li");
  li.className = "history-item";

  const date = document.createElement("div");
  date.className = "history-date";
  date.textContent = t("history_changed_on", [new Date(historyEntry.changedAt).toLocaleDateString()]);

  const pwRow = document.createElement("div");
  pwRow.className = "history-password-row";

  const pwText = document.createElement("span");
  pwText.className = "history-password monospace";
  pwText.textContent = "•".repeat(10);
  pwText.dataset.revealed = "false";

  const revealBtn = document.createElement("button");
  revealBtn.className = "icon-btn";
  revealBtn.title = t("action_show_hide_password");
  revealBtn.innerHTML = ICON_EYE_SVG;
  revealBtn.addEventListener("click", () => {
    const revealed = pwText.dataset.revealed === "true";
    pwText.textContent = revealed ? "•".repeat(10) : historyEntry.password;
    pwText.dataset.revealed = revealed ? "false" : "true";
  });

  const copyBtn = document.createElement("button");
  copyBtn.className = "icon-btn";
  copyBtn.title = t("action_copy_password");
  copyBtn.innerHTML = ICON_COPY_SVG;
  copyBtn.addEventListener("click", () => copyToClipboard(historyEntry.password, t("status_password_copied")));

  pwRow.append(pwText, revealBtn, copyBtn);
  li.append(date, pwRow);
  return li;
}

els.detailHistoryToggle.addEventListener("click", () => {
  const collapsed = els.detailHistoryList.hidden;
  els.detailHistoryList.hidden = !collapsed;
  els.detailHistoryChevron.classList.toggle("icon-chevron-open", collapsed);
});

els.detailBackBtn.addEventListener("click", () => showList());

els.detailRevealBtn.addEventListener("click", () => {
  const revealed = els.detailPassword.dataset.revealed === "true";
  els.detailPassword.textContent = revealed ? "•".repeat(10) : selectedEntry.password;
  els.detailPassword.dataset.revealed = revealed ? "false" : "true";
});

document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const field = btn.dataset.copy;
    const value = field === "password" ? selectedEntry.password : selectedEntry[field];
    const messageKey = { username: "status_username_copied", password: "status_password_copied", url: "status_url_copied" }[field];
    copyToClipboard(value, t(messageKey));
  });
});

function copyToClipboard(value, message) {
  navigator.clipboard.writeText(value || "").then(
    () => setStatus(message),
    () => setStatus(t("status_copy_failed"), true)
  );
}

els.detailDeleteBtn.addEventListener("click", async () => {
  if (!selectedEntry) return;
  if (!confirm(t("confirm_delete_title", [selectedEntry.website]))) return;

  setStatus(t("status_deleting"));
  try {
    const res = await sendToBackground("PASS_DELETE_ENTRY", { id: selectedEntry.id });
    state.entries = res.entries;
    setStatus(t("status_entry_deleted"));
    showList();
  } catch (e) {
    setStatus(e.message, true);
  }
});

async function addTotp() {
  const uri = window.prompt(t("mfa_prompt_uri"));
  if (!uri) return;

  setStatus(t("status_adding_mfa"));
  try {
    const res = await sendToBackground("PASS_ADD_TOTP", { id: selectedEntry.id, uri });
    state.entries = res.entries;
    selectedEntry = await sendToBackground("PASS_GET_ENTRY", { id: selectedEntry.id });
    setStatus(t("status_mfa_added"));
    renderTotpSection();
  } catch (e) {
    setStatus(e.message, true);
  }
}

// ---------- Detail edit mode ----------

els.detailEditBtn.addEventListener("click", () => {
  els.editWebsite.value = selectedEntry.website;
  els.editUrl.value = selectedEntry.url || "";
  els.editUsername.value = selectedEntry.username;
  els.editPassword.value = "";
  els.editPassword.type = "password";
  els.editAdditionalUrls.value = (selectedEntry.additionalUrls || []).join("\n");
  els.editNotes.value = selectedEntry.notes || "";

  els.detailViewFields.hidden = true;
  els.detailEditFields.hidden = false;
});

els.editCancelBtn.addEventListener("click", () => {
  els.detailViewFields.hidden = false;
  els.detailEditFields.hidden = true;
});

els.editGenerateBtn.addEventListener("click", () => {
  els.editPassword.value = generatePassword();
  els.editPassword.type = "text";
});

els.editSaveBtn.addEventListener("click", async () => {
  const website = els.editWebsite.value.trim();
  const url = els.editUrl.value.trim();
  const username = els.editUsername.value.trim();
  const password = els.editPassword.value; // empty = leave unchanged
  const additionalUrls = parseUrlsTextarea(els.editAdditionalUrls.value);
  const notes = els.editNotes.value;

  if (!website || !username) {
    setStatus(t("status_website_username_required"), true);
    return;
  }

  setStatus(t("status_saving"));
  try {
    const res = await sendToBackground("PASS_UPDATE_ENTRY", {
      id: selectedEntry.id,
      website,
      url,
      username,
      password,
      additionalUrls,
      notes,
    });
    state.entries = res.entries;
    selectedEntry = await sendToBackground("PASS_GET_ENTRY", { id: selectedEntry.id });
    setStatus(t("status_entry_updated"));
    renderDetail();
    loadHistory(selectedEntry.id); // a password change just archived one
  } catch (e) {
    setStatus(e.message, true);
  }
});

// ---------- Fill active tab (used by content.js's in-page picker too, via
// background — this direct path stays for a manual "open popup and pick an
// entry" flow) ----------

async function fillActiveTab(id) {
  try {
    const entry = await sendToBackground("PASS_GET_ENTRY", { id });
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const reply = await sendFillMessage(tab.id, entry);
    setStatus(reply && reply.filled ? t("status_filled") : t("status_no_login_form"), !reply?.filled);
  } catch (e) {
    setStatus(e.message, true);
  }
}

const FILL_MESSAGE_RETRY = (entry) => ({
  type: "PASS_FILL_CREDENTIALS",
  username: entry.username,
  password: entry.password,
});

async function sendFillMessage(tabId, entry) {
  try {
    return await chrome.tabs.sendMessage(tabId, FILL_MESSAGE_RETRY(entry));
  } catch {
    // Tabs opened before the extension was loaded/reloaded never got the
    // declared content script injected — inject it on demand instead of
    // making the user reload the page, then retry once.
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
    return await chrome.tabs.sendMessage(tabId, FILL_MESSAGE_RETRY(entry));
  }
}
