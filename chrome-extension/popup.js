// Talks to the pass-native-host process over Chrome's native messaging
// API. Every call is a stateless request/response: the master password is
// sent with each command (kept only in this popup's memory and in
// chrome.storage.session, which is wiped when the browser closes) rather
// than relying on a long-lived unlocked session in the native host.

const NATIVE_HOST = "com.antoniopicone.pass_native_host";
const SESSION_TTL_MS = 5 * 60 * 1000; // re-prompt for the master password after 5 minutes idle

const els = {
  lockedView: document.getElementById("locked-view"),
  unlockedView: document.getElementById("unlocked-view"),
  vaultPath: document.getElementById("vault-path"),
  masterPassword: document.getElementById("master-password"),
  unlockBtn: document.getElementById("unlock-btn"),
  initBtn: document.getElementById("init-btn"),
  lockBtn: document.getElementById("lock-btn"),
  status: document.getElementById("status"),
  search: document.getElementById("search"),
  entryList: document.getElementById("entry-list"),
  mergePath: document.getElementById("merge-path"),
  mergeBtn: document.getElementById("merge-btn"),
};

let session = null; // { vaultPath, masterPassword, unlockedAt }
let entries = [];
let currentDomain = "";

init();

async function init() {
  currentDomain = await getActiveTabDomain();

  const stored = await chrome.storage.session.get("passSession");
  if (stored.passSession && Date.now() - stored.passSession.unlockedAt < SESSION_TTL_MS) {
    session = stored.passSession;
    els.vaultPath.value = session.vaultPath;
    try {
      await refreshEntries();
      showUnlocked();
      return;
    } catch (e) {
      // Session no longer valid (vault moved, etc.) — fall through to locked view.
      session = null;
      await chrome.storage.session.remove("passSession");
    }
  }

  els.vaultPath.value = "passwords.vault";
  showLocked();
}

function showLocked() {
  els.lockedView.hidden = false;
  els.unlockedView.hidden = true;
}

function showUnlocked() {
  els.lockedView.hidden = true;
  els.unlockedView.hidden = false;
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

els.unlockBtn.addEventListener("click", async () => {
  const vaultPath = els.vaultPath.value.trim();
  const masterPassword = els.masterPassword.value;
  if (!vaultPath || !masterPassword) {
    setStatus("Vault path and master password are required.", true);
    return;
  }

  setStatus("Unlocking…");
  try {
    const res = await sendNative({ cmd: "unlockVault", vaultPath, masterPassword });
    entries = res.entries || [];
    session = { vaultPath, masterPassword, unlockedAt: Date.now() };
    await chrome.storage.session.set({ passSession: session });
    els.masterPassword.value = "";
    setStatus("");
    renderEntries();
    showUnlocked();
  } catch (e) {
    setStatus(e.message, true);
  }
});

els.initBtn.addEventListener("click", async () => {
  const vaultPath = els.vaultPath.value.trim();
  const masterPassword = els.masterPassword.value;
  if (!vaultPath || !masterPassword) {
    setStatus("Vault path and master password are required.", true);
    return;
  }
  if (masterPassword.length < 8) {
    setStatus("Master password must be at least 8 characters.", true);
    return;
  }

  setStatus("Creating vault…");
  try {
    await sendNative({ cmd: "initVault", vaultPath, masterPassword });
    setStatus("Vault created.");
    els.unlockBtn.click();
  } catch (e) {
    setStatus(e.message, true);
  }
});

els.lockBtn.addEventListener("click", async () => {
  session = null;
  entries = [];
  await chrome.storage.session.remove("passSession");
  els.masterPassword.value = "";
  setStatus("");
  showLocked();
});

els.search.addEventListener("input", renderEntries);

els.mergeBtn.addEventListener("click", async () => {
  const otherPath = els.mergePath.value.trim();
  if (!session || !otherPath) return;

  setStatus("Merging…");
  try {
    const res = await sendNative({
      cmd: "mergeFromFile",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      otherPath,
    });
    setStatus(
      `Merge done — added ${res.added}, updated ${res.updated}, ` +
        `${res.conflicts} conflict(s) resolved.`
    );
    await refreshEntries();
    renderEntries();
  } catch (e) {
    setStatus(e.message, true);
  }
});

async function refreshEntries() {
  const res = await sendNative({
    cmd: "unlockVault",
    vaultPath: session.vaultPath,
    masterPassword: session.masterPassword,
  });
  entries = res.entries || [];
}

function renderEntries() {
  const query = els.search.value.trim().toLowerCase();
  els.entryList.innerHTML = "";

  const matches = entries.filter(
    (e) =>
      !query ||
      e.website.toLowerCase().includes(query) ||
      e.username.toLowerCase().includes(query) ||
      e.url.toLowerCase().includes(query)
  );

  matches.sort((a, b) => {
    const aMatch = currentDomain && a.url.includes(currentDomain);
    const bMatch = currentDomain && b.url.includes(currentDomain);
    if (aMatch !== bMatch) return aMatch ? -1 : 1;
    return a.website.localeCompare(b.website);
  });

  if (matches.length === 0) {
    els.entryList.innerHTML = '<li class="empty">No entries found.</li>';
    return;
  }

  for (const entry of matches) {
    const li = document.createElement("li");
    li.className = "entry";

    const info = document.createElement("div");
    info.className = "entry-info";
    const strong = document.createElement("strong");
    strong.textContent = entry.website + (entry.hasTotp ? " 🔐" : "");
    const span = document.createElement("span");
    span.textContent = entry.username;
    info.append(strong, span);

    const actions = document.createElement("div");
    actions.className = "entry-actions";

    const fillBtn = document.createElement("button");
    fillBtn.textContent = "Fill";
    fillBtn.addEventListener("click", () => fillActiveTab(entry.id));

    const copyBtn = document.createElement("button");
    copyBtn.textContent = "Copy";
    copyBtn.className = "secondary";
    copyBtn.addEventListener("click", () => copyPassword(entry.id));

    actions.append(fillBtn, copyBtn);

    const mfaBtn = document.createElement("button");
    mfaBtn.className = "secondary";
    if (entry.hasTotp) {
      mfaBtn.textContent = "MFA";
      mfaBtn.title = "Copy the current MFA code";
      mfaBtn.addEventListener("click", () => copyTotpCode(entry.id));
    } else {
      mfaBtn.textContent = "+MFA";
      mfaBtn.title = "Attach an MFA/TOTP secret (paste the otpauth:// URI)";
      mfaBtn.addEventListener("click", () => addTotp(entry.id));
    }
    actions.append(mfaBtn);

    li.append(info, actions);
    els.entryList.appendChild(li);
  }
}

async function fillActiveTab(id) {
  setStatus("Filling…");
  try {
    const res = await sendNative({
      cmd: "getEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const reply = await chrome.tabs.sendMessage(tab.id, {
      type: "PASS_FILL_CREDENTIALS",
      username: res.entry.username,
      password: res.entry.password,
    });
    setStatus(reply && reply.filled ? "Filled." : "No login form found on this page.", !reply?.filled);
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function copyPassword(id) {
  setStatus("Copying…");
  try {
    const res = await sendNative({
      cmd: "getEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    await navigator.clipboard.writeText(res.entry.password);
    setStatus("Password copied to clipboard.");
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function copyTotpCode(id) {
  setStatus("Fetching MFA code…");
  try {
    const res = await sendNative({
      cmd: "getEntry",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
    });
    if (!res.entry.totp) {
      setStatus("No MFA code configured for this entry.", true);
      return;
    }
    await navigator.clipboard.writeText(res.entry.totp.code);
    setStatus(`MFA code copied (expires in ${res.entry.totp.secondsRemaining}s).`);
  } catch (e) {
    setStatus(e.message, true);
  }
}

async function addTotp(id) {
  const uri = window.prompt(
    "Paste the otpauth:// URI from the service's MFA setup page " +
      '(usually behind a "can\'t scan the code?" / manual entry link):'
  );
  if (!uri) return;

  setStatus("Adding MFA code…");
  try {
    await sendNative({
      cmd: "addTotpUri",
      vaultPath: session.vaultPath,
      masterPassword: session.masterPassword,
      id,
      uri,
    });
    setStatus("MFA code added.");
    await refreshEntries();
    renderEntries();
  } catch (e) {
    setStatus(e.message, true);
  }
}

function setStatus(message, isError = false) {
  els.status.textContent = message;
  els.status.className = isError ? "status error" : "status";
}
