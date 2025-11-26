"use strict";

const express = require("express");
const path = require("path");
const { Keychain } = require("./password-manager");

const app = express();
const PORT = 3000;

// Parse JSON bodies
app.use(express.json());

// Serve static files from "public" folder
app.use(express.static(path.join(__dirname, "public")));

// In-memory state for demo (NOT for real-world use)
let keychain = null;
let dumpRepr = null;
let dumpChecksum = null;

// POST /init  { password }
app.post("/api/init", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });

  try {
    keychain = await Keychain.init(password);
    dumpRepr = null;
    dumpChecksum = null;
    return res.json({ ok: true, message: "Keychain initialized" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Init failed" });
  }
});

// POST /api/set  { domain, password }
app.post("/api/set", async (req, res) => {
  if (!keychain) return res.status(400).json({ error: "Keychain not initialized" });
  const { domain, password } = req.body;
  if (!domain || !password) return res.status(400).json({ error: "Domain and password required" });

  try {
    await keychain.set(domain, password);
    return res.json({ ok: true, message: `Stored password for ${domain}` });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Set failed" });
  }
});

// POST /api/get  { domain }
app.post("/api/get", async (req, res) => {
  if (!keychain) return res.status(400).json({ error: "Keychain not initialized" });
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: "Domain required" });

  try {
    const pw = await keychain.get(domain);
    return res.json({ ok: true, domain, password: pw });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Get failed" });
  }
});

// POST /api/remove  { domain }
app.post("/api/remove", async (req, res) => {
  if (!keychain) return res.status(400).json({ error: "Keychain not initialized" });
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: "Domain required" });

  try {
    const removed = await keychain.remove(domain);
    return res.json({ ok: true, removed });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Remove failed" });
  }
});

// POST /api/dump  {}
app.post("/api/dump", async (req, res) => {
  if (!keychain) return res.status(400).json({ error: "Keychain not initialized" });

  try {
    const [repr, checksum] = await keychain.dump();
    dumpRepr = repr;
    dumpChecksum = checksum;
    return res.json({ ok: true, repr, checksum });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Dump failed" });
  }
});

// POST /api/reset-session  {}
// Called on page load/refresh to clear any unlocked keychain from memory.
// We keep dumpRepr + dumpChecksum so user can load from dump later.
app.post("/api/reset-session", (req, res) => {
  keychain = null;
  return res.json({ ok: true, message: "Keychain cleared from memory (vault locked)." });
});



// POST /api/load  { password }
app.post("/api/load", async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });
  if (!dumpRepr || !dumpChecksum) {
    return res.status(400).json({ error: "No saved dump in memory yet" });
  }

  try {
    // to refresh and behave like an actual app
    const loaded = await Keychain.load(password, dumpRepr, dumpChecksum);
    keychain = loaded; //only set on successful load
    return res.json({ ok: true, message: "Keychain loaded from dump" });
    } catch (e) {
        //clear any partial state on failure
        keychain = null;
        return res.status(400).json({ error: "Load failed: " + e.message });
    }
});


 

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
