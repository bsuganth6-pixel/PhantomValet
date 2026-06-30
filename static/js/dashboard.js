// PhantomVault — Dashboard logic

let currentEntries = [];
let editingEntryId = null;
let lastGeneratedPassword = "";

// ════════════════════════════════════════════════════════════
//  LOAD + RENDER ENTRY LIST
// ════════════════════════════════════════════════════════════

async function loadEntries(query = "") {
  const url = query ? `/api/vault/entries?q=${encodeURIComponent(query)}` : "/api/vault/entries";
  const result = await PS.getJSON(url);

  if (result.error) {
    if (result.error.includes("locked")) { window.location.href = "/"; return; }
    PS.toast(result.error, "error");
    return;
  }

  currentEntries = result.entries;
  renderEntries();
}

function renderEntries() {
  const list = document.getElementById("entryList");
  const empty = document.getElementById("emptyState");

  if (currentEntries.length === 0) {
    list.innerHTML = "";
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";

  list.innerHTML = currentEntries.map(e => {
    const initial = (e.site[0] || "?").toUpperCase();
    return `
    <div class="entry-card" data-id="${e.id}">
      <div class="entry-icon">${PS.esc(initial)}</div>
      <div class="entry-info">
        <div class="entry-site">${PS.esc(e.site)}</div>
        <div class="entry-username">${PS.esc(e.username || "—")}</div>
      </div>
      <div class="entry-pw-display" id="pwdisplay-${e.id}">••••••••••••</div>
      <div class="entry-actions">
        <button class="icon-btn" onclick="toggleReveal('${e.id}')" title="Show/Hide password"><i class="fa-solid fa-eye" id="eyeicon-${e.id}"></i></button>
        <button class="icon-btn" onclick="copyEntryPassword('${e.id}')" title="Copy password"><i class="fa-solid fa-copy"></i></button>
        <button class="icon-btn" onclick="editEntry('${e.id}')" title="Edit"><i class="fa-solid fa-pen"></i></button>
        <button class="icon-btn" onclick="confirmDelete('${e.id}', '${PS.esc(e.site)}')" title="Delete"><i class="fa-solid fa-trash"></i></button>
      </div>
    </div>`;
  }).join("");
}

let _searchDebounce = null;
function debouncedSearch() {
  clearTimeout(_searchDebounce);
  _searchDebounce = setTimeout(() => {
    loadEntries(document.getElementById("searchInput").value);
  }, 250);
}

// ════════════════════════════════════════════════════════════
//  REVEAL / COPY (fetches the real password only on demand)
// ════════════════════════════════════════════════════════════

const _revealedCache = {}; // entry_id -> password (cleared when navigating away/locking)

async function toggleReveal(entryId) {
  const display = document.getElementById(`pwdisplay-${entryId}`);
  const icon = document.getElementById(`eyeicon-${entryId}`);
  const isRevealed = display.classList.contains("revealed");

  if (isRevealed) {
    display.textContent = "••••••••••••";
    display.classList.remove("revealed");
    icon.className = "fa-solid fa-eye";
    return;
  }

  let password = _revealedCache[entryId];
  if (!password) {
    const result = await PS.getJSON(`/api/vault/entries/${entryId}/reveal`);
    if (result.error) { PS.toast(result.error, "error"); return; }
    password = result.password;
    _revealedCache[entryId] = password;
  }

  display.textContent = password;
  display.classList.add("revealed");
  icon.className = "fa-solid fa-eye-slash";

  // Auto-hide after 15s even if user doesn't click again (shoulder-surfing protection)
  setTimeout(() => {
    if (display.classList.contains("revealed")) {
      display.textContent = "••••••••••••";
      display.classList.remove("revealed");
      icon.className = "fa-solid fa-eye";
    }
  }, 15000);
}

async function copyEntryPassword(entryId) {
  let password = _revealedCache[entryId];
  if (!password) {
    const result = await PS.getJSON(`/api/vault/entries/${entryId}/reveal`);
    if (result.error) { PS.toast(result.error, "error"); return; }
    password = result.password;
    _revealedCache[entryId] = password;
  }
  PS.copyWithAutoClear(password, "Password", 20);
}

// ════════════════════════════════════════════════════════════
//  ADD / EDIT ENTRY MODAL
// ════════════════════════════════════════════════════════════

function openEntryModal() {
  editingEntryId = null;
  document.getElementById("modalTitle").textContent = "Add Entry";
  document.getElementById("entryId").value = "";
  document.getElementById("entrySite").value = "";
  document.getElementById("entryUsername").value = "";
  document.getElementById("entryPassword").value = "";
  document.getElementById("entryNotes").value = "";
  document.getElementById("entryPassword").type = "password";
  document.getElementById("entryPwEyeIcon").className = "fa-solid fa-eye";
  document.getElementById("modalStrengthMeter").style.display = "none";
  document.getElementById("entryModal").classList.add("active");
}

async function editEntry(entryId) {
  editingEntryId = entryId;
  const entry = currentEntries.find(e => e.id === entryId);
  if (!entry) return;

  let password = _revealedCache[entryId];
  if (!password) {
    const result = await PS.getJSON(`/api/vault/entries/${entryId}/reveal`);
    if (result.error) { PS.toast(result.error, "error"); return; }
    password = result.password;
    _revealedCache[entryId] = password;
  }

  document.getElementById("modalTitle").textContent = "Edit Entry";
  document.getElementById("entryId").value = entryId;
  document.getElementById("entrySite").value = entry.site;
  document.getElementById("entryUsername").value = entry.username;
  document.getElementById("entryPassword").value = password;
  document.getElementById("entryNotes").value = entry.notes || "";
  checkModalStrength();
  document.getElementById("entryModal").classList.add("active");
}

function closeEntryModal() {
  document.getElementById("entryModal").classList.remove("active");
}

function toggleEntryPasswordVisibility() {
  const input = document.getElementById("entryPassword");
  const icon = document.getElementById("entryPwEyeIcon");
  if (input.type === "password") {
    input.type = "text"; icon.className = "fa-solid fa-eye-slash";
  } else {
    input.type = "password"; icon.className = "fa-solid fa-eye";
  }
}

let _strengthDebounce = null;
document.addEventListener("DOMContentLoaded", () => {
  const pwInput = document.getElementById("entryPassword");
  if (pwInput) pwInput.addEventListener("input", () => {
    clearTimeout(_strengthDebounce);
    _strengthDebounce = setTimeout(checkModalStrength, 200);
  });
});

async function checkModalStrength() {
  const pw = document.getElementById("entryPassword").value;
  const meter = document.getElementById("modalStrengthMeter");
  if (!pw) { meter.style.display = "none"; return; }
  meter.style.display = "block";

  const result = await PS.postJSON("/api/check-strength", { password: pw });
  applyStrengthUI(result.score, "modalStrengthFill", "modalStrengthLabel");
}

function applyStrengthUI(score, fillId, labelId) {
  const fill = document.getElementById(fillId);
  const label = document.getElementById(labelId);
  fill.style.width = score + "%";
  let color, text;
  if (score >= 80) { color = "#00FF88"; text = "VERY STRONG"; }
  else if (score >= 60) { color = "#00F5FF"; text = "STRONG"; }
  else if (score >= 40) { color = "#FFD23F"; text = "MODERATE"; }
  else if (score >= 20) { color = "#FF9F1C"; text = "WEAK"; }
  else { color = "#FF3B5C"; text = "VERY WEAK"; }
  fill.style.background = color;
  label.textContent = text;
  label.style.color = color;
}

async function saveEntry() {
  const site = document.getElementById("entrySite").value.trim();
  const username = document.getElementById("entryUsername").value.trim();
  const password = document.getElementById("entryPassword").value;
  const notes = document.getElementById("entryNotes").value.trim();

  if (!site) { PS.toast("Site name is required.", "error"); return; }

  const btn = document.getElementById("saveEntryBtn");
  btn.disabled = true;

  let result;
  if (editingEntryId) {
    result = await PS.putJSON(`/api/vault/entries/${editingEntryId}`, { site, username, password, notes });
    delete _revealedCache[editingEntryId];
  } else {
    result = await PS.postJSON("/api/vault/entries", { site, username, password, notes });
  }

  btn.disabled = false;

  if (result.error) {
    PS.toast(result.error, "error");
    return;
  }

  PS.toast(editingEntryId ? "Entry updated." : "Entry added.", "success");
  closeEntryModal();
  loadEntries(document.getElementById("searchInput").value);
}

async function confirmDelete(entryId, siteName) {
  if (!confirm(`Delete the entry for "${siteName}"? This cannot be undone.`)) return;
  const result = await PS.del(`/api/vault/entries/${entryId}`);
  if (result.error) { PS.toast(result.error, "error"); return; }
  delete _revealedCache[entryId];
  PS.toast("Entry deleted.", "success");
  loadEntries(document.getElementById("searchInput").value);
}

// ════════════════════════════════════════════════════════════
//  PASSWORD GENERATOR MODAL
// ════════════════════════════════════════════════════════════

function openGenerator() {
  document.getElementById("generatorModal").classList.add("active");
  generatePassword();
}
function closeGenerator() {
  document.getElementById("generatorModal").classList.remove("active");
}

async function generatePassword() {
  const payload = {
    length: parseInt(document.getElementById("genLength").value, 10),
    use_upper: document.getElementById("genUpper").checked,
    use_lower: document.getElementById("genLower").checked,
    use_digits: document.getElementById("genDigits").checked,
    use_symbols: document.getElementById("genSymbols").checked,
    avoid_ambiguous: document.getElementById("genAmbiguous").checked,
  };
  const result = await PS.postJSON("/api/generate-password", payload);
  if (result.error) { PS.toast(result.error, "error"); return; }

  lastGeneratedPassword = result.password;
  document.getElementById("generatedDisplay").textContent = result.password;
  applyStrengthUI(result.strength.score, "genStrengthFill", "genStrengthLabel");
}

document.addEventListener("click", (e) => {
  if (e.target && e.target.id === "generatedDisplay" && lastGeneratedPassword) {
    PS.copyWithAutoClear(lastGeneratedPassword, "Generated password", 20);
  }
});

function useGeneratedPassword() {
  if (!lastGeneratedPassword) return;
  document.getElementById("entryPassword").value = lastGeneratedPassword;
  document.getElementById("entryPassword").type = "text";
  document.getElementById("entryPwEyeIcon").className = "fa-solid fa-eye-slash";
  checkModalStrength();
  closeGenerator();
}

// ════════════════════════════════════════════════════════════
//  SETTINGS / CHANGE MASTER PASSWORD
// ════════════════════════════════════════════════════════════

function openSettings() {
  document.getElementById("newMasterPassword").value = "";
  document.getElementById("confirmMasterPassword").value = "";
  document.getElementById("settingsError").style.display = "none";
  document.getElementById("settingsModal").classList.add("active");
}
function closeSettings() {
  document.getElementById("settingsModal").classList.remove("active");
}

async function changeMasterPassword() {
  const newPw = document.getElementById("newMasterPassword").value;
  const confirm = document.getElementById("confirmMasterPassword").value;
  const errBox = document.getElementById("settingsError");

  if (newPw.length < 8) { errBox.textContent = "Must be at least 8 characters."; errBox.style.display = "block"; return; }
  if (newPw !== confirm) { errBox.textContent = "Passwords do not match."; errBox.style.display = "block"; return; }

  const result = await PS.postJSON("/api/vault/change-master-password", {
    new_master_password: newPw, confirm_password: confirm,
  });

  if (result.error) { errBox.textContent = result.error; errBox.style.display = "block"; return; }

  PS.toast("Master password updated.", "success");
  closeSettings();
}

// ════════════════════════════════════════════════════════════
//  LOCK / IDLE COUNTDOWN
// ════════════════════════════════════════════════════════════

async function lockVault() {
  await PS.postJSON("/api/vault/lock", {});
  window.location.href = "/";
}

async function pollIdleStatus() {
  const result = await PS.getJSON("/api/vault/status");
  const el = document.getElementById("idleCountdown");
  if (!result.unlocked) {
    window.location.href = "/";
    return;
  }
  const remaining = result.idle_seconds_remaining;
  el.textContent = `AUTO-LOCK IN ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`;
  el.classList.remove("warn", "critical");
  if (remaining < 30) el.classList.add("critical");
  else if (remaining < 60) el.classList.add("warn");
}

// Reset the idle timer on any user activity by pinging status (which calls touch())
let _activityDebounce = null;
["click", "keydown", "mousemove"].forEach(evt => {
  document.addEventListener(evt, () => {
    clearTimeout(_activityDebounce);
    _activityDebounce = setTimeout(() => fetch("/api/vault/status"), 1000);
  });
});

// ════════════════════════════════════════════════════════════
//  INIT
// ════════════════════════════════════════════════════════════

loadEntries();
pollIdleStatus();
setInterval(pollIdleStatus, 10000);
