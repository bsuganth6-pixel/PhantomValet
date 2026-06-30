// PhantomVault — Shared frontend utilities

const PS = {
  esc(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  },

  async postJSON(url, body) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      return await resp.json();
    } catch (e) {
      return { error: "Network error — is the server running?" };
    }
  },

  async putJSON(url, body) {
    try {
      const resp = await fetch(url, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      return await resp.json();
    } catch (e) {
      return { error: "Network error." };
    }
  },

  async del(url) {
    try {
      const resp = await fetch(url, { method: "DELETE" });
      return await resp.json();
    } catch (e) {
      return { error: "Network error." };
    }
  },

  async getJSON(url) {
    try {
      const resp = await fetch(url);
      return await resp.json();
    } catch (e) {
      return { error: "Network error." };
    }
  },

  setLoading(loaderEl, btnEl, isLoading) {
    if (loaderEl) loaderEl.classList.toggle("active", isLoading);
    if (btnEl) btnEl.disabled = isLoading;
  },

  // ── Toast notifications ──
  toast(message, type = "info", duration = 3000) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    const icon = type === "success" ? "circle-check" : type === "error" ? "circle-exclamation" : "circle-info";
    el.innerHTML = `<i class="fa-solid fa-${icon}"></i><span>${this.esc(message)}</span>`;
    container.appendChild(el);
    setTimeout(() => {
      el.style.animation = "toastOut 0.25s ease forwards";
      setTimeout(() => el.remove(), 250);
    }, duration);
  },

  // ── Copy to clipboard WITH auto-clear after N seconds ──
  // Prevents a sensitive password from sitting in the clipboard indefinitely,
  // where other apps (clipboard managers, malware) could read it later.
  _clipboardClearTimer: null,
  async copyWithAutoClear(text, label = "Password", clearAfterSeconds = 20) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      this.toast("Clipboard access denied by browser.", "error");
      return;
    }

    this.toast(`${label} copied — clipboard clears in ${clearAfterSeconds}s`, "success", clearAfterSeconds * 1000);

    if (this._clipboardClearTimer) clearTimeout(this._clipboardClearTimer);
    this._clipboardClearTimer = setTimeout(async () => {
      try {
        // Only clear if the clipboard still contains what we copied
        // (avoids wiping something the user copied from elsewhere since)
        const current = await navigator.clipboard.readText().catch(() => null);
        if (current === text) {
          await navigator.clipboard.writeText(" ");
        }
      } catch (e) {
        // Clipboard read permission may be denied — best-effort only.
      }
    }, clearAfterSeconds * 1000);
  },
};
