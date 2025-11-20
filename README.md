📌 Secure Password Manager — PBKDF2 + AES-GCM + HMAC

A secure password management core written in Node.js using the WebCrypto SubtleCrypto API.
This system protects stored credentials using industry-grade cryptography:

🔐 AES-GCM per-record authenticated encryption

🧠 PBKDF2 key derivation from a master password

🛡️ HMAC-SHA256 to hide domain names securely

🚫 No plaintext or sensitive metadata stored in dumps

🔍 Swap-attack & rollback-attack protection included

This is an academic project focused on learning secure system design — not a production password vault.

✨ Features
Feature	Status
Store & retrieve per-domain passwords	✔
Strong KDF using PBKDF2 + random salt	✔
Authenticated AES-GCM encryption	✔
Domain privacy using HMAC hashing	✔
Password length obfuscation with padding	✔
Dump & restore using JSON + checksum	✔
Protection against swap/rollback attacks	✔
Optional demo UI for interactive use	✔
🧠 Security Overview
Attack Prevented	Defense Applied
Swap Attack	AES-GCM AAD binds encrypted values to domain HMAC
Rollback Attack	SHA-256 checksum verifies dump integrity
Password Length Leakage	Padding to fixed 64 bytes per entry
Master Password Guessing	PBKDF2 with 100k iterations + salt
Domain Enumeration	Encrypted keys + HMAC-SHA256 tags

Passwords and domain names are never stored in plaintext — not even in serialized form.

🚀 Running the Core
1️⃣ Install dependencies
npm install

2️⃣ Run automated tests (Mocha)
npm test


All required tests should pass:

11 passing

🎛 Optional: Interactive UI Demo

A small Node/Express frontend is included to demonstrate functionality visually.

Start the server
node server.js


Then open:

👉 http://localhost:3000/

You can:

Initialize a keychain

Store passwords for domains

Retrieve or remove entries

Dump secure database state

Reload using master password

<img width="1330" height="947" alt="image" src="https://github.com/user-attachments/assets/1ae2efd4-1d08-4c8a-8091-2b7d391c3227" />


This UI is for demo and learning only — it does not store data permanently unless you add file persistence.

📂 Project Structure
Proj1_Starter/
│
├─ password-manager.js     # Main secure keychain implementation (graded)
├─ lib.js                  # Helper utilities for encoding / random bytes
├─ test/
│   └─ test-password-manager.js  # Provided unit tests
├─ server.js               # Optional UI backend
└─ public/
    ├─ index.html          # UI for visual interaction
    └─ app.js              # Frontend logic for interacting with server


Only password-manager.js is required for academic grading.

💡 Future Improvements

Persist encrypted dump to localStorage or a database

Allow multi-user shared access with per-user AES keys

Encrypt domain list and perform blind lookups

Replace PBKDF2 with Argon2 for stronger brute-force resistance

Build full UI/UX password manager app

✍️ Author

Edgar — Computer Science & Informatics Student
Project completed as part of a security-focused coursework assignment.

⚠️ Disclaimer

This project is for educational purposes only.
Do not store real personal passwords in this demo.
