function appendLog(message, type = "info") {
  const logDiv = document.getElementById("log");
  const line = document.createElement("div");
  line.className = "log-line " + type;
  line.textContent = message;
  logDiv.appendChild(line);
  logDiv.scrollTop = logDiv.scrollHeight;
}

function setBadge(id, text, variant = "neutral") {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.classList.remove("success", "error", "neutral");
  el.classList.add(variant);
}

async function postJSON(url, obj) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(obj)
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

window.addEventListener("DOMContentLoaded", () => {
  const masterPasswordInput = document.getElementById("masterPassword");

  // 🔹 NEW: tell server to lock/clear any in-memory keychain on page load
  (async () => {
    try {
      await postJSON("/api/reset-session", {});
      appendLog("[Session] Vault locked on page load.", "info");
    } catch (e) {
      // If server not started yet, this will fail; you can ignore or log if you want.
      appendLog("[Session] Could not reset session: " + e.message, "err");
    }
  })();

  // Init button
  document.getElementById("btnInit").addEventListener("click", async () => {
    const pw = masterPasswordInput.value;
    if (!pw) {
      alert("Enter a master password first.");
      return;
    }
    try {
      const result = await postJSON("/api/init", { password: pw });
      appendLog("[Init] " + result.message, "ok");
      setBadge("badgeKeychain", "Keychain: Initialized", "success");
    } catch (e) {
      appendLog("[Init] Error: " + e.message, "err");
      setBadge("badgeKeychain", "Keychain: Error", "error");
    }
  });

  // Save / update password
  document.getElementById("btnSet").addEventListener("click", async () => {
    const domain = document.getElementById("domainSet").value.trim();
    const pw = document.getElementById("passwordSet").value;
    if (!domain || !pw) {
      alert("Enter both domain and password.");
      return;
    }
    try {
      const result = await postJSON("/api/set", { domain, password: pw });
      appendLog("[Set] " + result.message, "ok");
    } catch (e) {
      appendLog("[Set] Error: " + e.message, "err");
    }
  });

  // Get password
  document.getElementById("btnGet").addEventListener("click", async () => {
    const domain = document.getElementById("domainGet").value.trim();
    if (!domain) {
      alert("Enter domain.");
      return;
    }
    try {
      const result = await postJSON("/api/get", { domain });
      appendLog("[Get] " + domain + " -> " + JSON.stringify(result.password), "info");
    } catch (e) {
      appendLog("[Get] Error: " + e.message, "err");
    }
  });

  // Remove password
  document.getElementById("btnRemove").addEventListener("click", async () => {
    const domain = document.getElementById("domainGet").value.trim();
    if (!domain) {
      alert("Enter domain.");
      return;
    }
    try {
      const result = await postJSON("/api/remove", { domain });
      appendLog("[Remove] " + domain + " removed? " + result.removed, "info");
    } catch (e) {
      appendLog("[Remove] Error: " + e.message, "err");
    }
  });

  // Dump
  document.getElementById("btnDump").addEventListener("click", async () => {
    try {
      const result = await postJSON("/api/dump", {});
      appendLog("[Dump] Saved dump in server memory. JSON length = " + result.repr.length, "ok");
      setBadge("badgeDump", "Dump: Available", "success");
    } catch (e) {
      appendLog("[Dump] Error: " + e.message, "err");
      setBadge("badgeDump", "Dump: Error", "error");
    }
  });

  // Load from dump
  document.getElementById("btnLoad").addEventListener("click", async () => {
    const pw = masterPasswordInput.value;
    if (!pw) {
      alert("Enter a master password first.");
      return;
    }
    try {
      const result = await postJSON("/api/load", { password: pw });
      appendLog("[Load] " + result.message, "ok");
      setBadge("badgeKeychain", "Keychain: Loaded from dump", "success");
    } catch (e) {
      appendLog("[Load] Error: " + e.message, "err");
      setBadge("badgeKeychain", "Keychain: Load failed", "error");
    }
  });

  // Initial badge state
  setBadge("badgeKeychain", "Keychain: Not initialized", "neutral");
  setBadge("badgeDump", "Dump: None", "neutral");
});
