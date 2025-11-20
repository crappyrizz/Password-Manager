"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters
const PW_CHECK_STRING = "keychain password check"; // constant used to verify correct password

/********* Helper Crypto Functions ********/

// Derive a master key (32 bytes) from password + salt using PBKDF2 (only once per init/load)
async function deriveMasterKeyBytes(password, saltBuf, iterations) {
  const passwordKey = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBuf,
      iterations: iterations
    },
    passwordKey,
    256 // 32 bytes
  );

  return bits; // ArrayBuffer
}

// From PBKDF2 master output, derive two subkeys via HMAC(master, label):
// - one HMAC key for domains
// - one AES-GCM key for encrypting passwords
async function deriveSubkeysFromMaster(masterBytes) {
  // Use masterBytes as HMAC key for labels
  const masterHmacKey = await subtle.importKey(
    "raw",
    masterBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const domainLabelTag = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("domain-key"));
  const encLabelTag = await subtle.sign("HMAC", masterHmacKey, stringToBuffer("enc-key"));

  // Domain HMAC key (for HMAC(domain))
  const domainKey = await subtle.importKey(
    "raw",
    domainLabelTag,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  // AES-GCM key for encrypting passwords (use full 32 bytes as AES-256 key)
  const aesKey = await subtle.importKey(
    "raw",
    encLabelTag,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );

  return { domainKey, aesKey };
}

// Compute SHA-256 over some string and return base64-encoded digest
async function sha256Base64(str) {
  const hashBuf = await subtle.digest("SHA-256", stringToBuffer(str));
  return encodeBuffer(hashBuf);
}

// Pad password to fixed MAX_PASSWORD_LENGTH bytes (zeros at end)
function padPassword(password) {
  const buf = stringToBuffer(password); // Buffer
  if (buf.length > MAX_PASSWORD_LENGTH) {
    throw new Error("Password too long");
  }
  const padded = Buffer.alloc(MAX_PASSWORD_LENGTH);
  buf.copy(padded, 0, 0, buf.length); // rest stays zero
  return padded; // Buffer
}

// Remove trailing zero bytes (inverse of above padding)
function unpadPassword(paddedBuf) {
  const buf = Buffer.from(paddedBuf); // ensure Buffer
  let end = buf.length;
  while (end > 0 && buf[end - 1] === 0) {
    end--;
  }
  return buf.slice(0, end).toString();
}

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   *
   * We keep:
   *  - this.data  : public/serializable info (salt, iterations, kvs, pwCheck, etc.)
   *  - this.secrets: in-memory only keys (domainKey, aesKey)
   */
  constructor(saltBase64, iterations, domainKey, aesKey, kvsObj, pwCheckObj) {
    this.data = {
      salt: saltBase64,          // base64 salt
      iterations: iterations,    // PBKDF2 iterations
      kvs: kvsObj || {},         // key-value store: hmac(domain) -> { iv, ct }
      pwCheck: pwCheckObj || null // encrypted password-check object
    };

    this.secrets = {
      domainKey, // HMAC key for domain names
      aesKey     // AES-GCM key for passwords and pwCheck
    };
  }

  // Compute HMAC(domainName) as an ArrayBuffer
  async _computeDomainTag(name) {
    return subtle.sign("HMAC", this.secrets.domainKey, stringToBuffer(name));
  }

  // Create password check record (AES-GCM encryption of a fixed string)
  async _createPasswordCheck() {
    const iv = getRandomBytes(12); // Uint8Array
    const plaintext = stringToBuffer(PW_CHECK_STRING);
    const aad = stringToBuffer("pw-check");

    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: aad,
        tagLength: 128
      },
      this.secrets.aesKey,
      plaintext
    );

    return {
      iv: encodeBuffer(iv),
      ct: encodeBuffer(ciphertext)
    };
  }

  // Verify password check (throws if wrong password or tampered)
  async _verifyPasswordCheck(pwCheckObj) {
    const ivBuf = decodeBuffer(pwCheckObj.iv); // Buffer
    const ctBuf = decodeBuffer(pwCheckObj.ct); // Buffer
    const aad = stringToBuffer("pw-check");

    let plaintext;
    try {
      plaintext = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBuf,
          additionalData: aad,
          tagLength: 128
        },
        this.secrets.aesKey,
        ctBuf
      );
    } catch (e) {
      throw new Error("Invalid password or tampered password check");
    }

    const recovered = bufferToString(plaintext);
    if (recovered !== PW_CHECK_STRING) {
      throw new Error("Invalid password (password check mismatch)");
    }
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: Keychain
    */
  static async init(password) {
    // Generate random salt
    const saltBytes = getRandomBytes(16); // Uint8Array
    const saltBase64 = encodeBuffer(saltBytes);

    // Derive master key from password + salt
    const masterBytes = await deriveMasterKeyBytes(password, saltBytes, PBKDF2_ITERATIONS);

    // Derive subkeys
    const { domainKey, aesKey } = await deriveSubkeysFromMaster(masterBytes);

    // Empty KVS to start
    const kvsObj = {};

    // Create keychain instance
    const kc = new Keychain(saltBase64, PBKDF2_ITERATIONS, domainKey, aesKey, kvsObj, null);

    // Create password-check record and store it in data
    kc.data.pwCheck = await kc._createPasswordCheck();

    return kc;
  }

  /**
    * Loads the keychain state from the provided representation (repr).
    * repr is a JSON string returned from dump()[0].
    * trustedDataCheck (dump()[1]) is an optional SHA-256 checksum of repr.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck:   string (optional)
    * Return Type: Keychain (or throws on error)
    */
  static async load(password, repr, trustedDataCheck) {
    // 1. If checksum is provided, verify it (rollback protection)
    if (trustedDataCheck !== undefined) {
      const computed = await sha256Base64(repr);
      if (computed !== trustedDataCheck) {
        throw new Error("Checksum mismatch (possible rollback or tampering)");
      }
    }

    // 2. Parse JSON representation
    let obj;
    try {
      obj = JSON.parse(repr);
    } catch (e) {
      throw new Error("Invalid representation: JSON parse failed");
    }

    if (!obj || typeof obj !== "object" || !obj.kvs || !obj.salt) {
      throw new Error("Invalid representation: missing required fields");
    }

    const saltBase64 = obj.salt;
    const iterations = obj.iterations || PBKDF2_ITERATIONS;

    const saltBytes = decodeBuffer(saltBase64);

    // 3. Re-derive master + subkeys using provided password
    const masterBytes = await deriveMasterKeyBytes(password, saltBytes, iterations);
    const { domainKey, aesKey } = await deriveSubkeysFromMaster(masterBytes);

    const kvsObj = obj.kvs || {};
    const pwCheckObj = obj.pwCheck || null;

    // 4. Build Keychain instance
    const kc = new Keychain(saltBase64, iterations, domainKey, aesKey, kvsObj, pwCheckObj);

    // 5. Verify password (using pwCheck). If wrong, throw -> tests expect rejection.
    if (pwCheckObj) {
      await kc._verifyPasswordCheck(pwCheckObj);
    }

    return kc;
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function.
    * Return value: [reprJSON, sha256Checksum]
    *
    * Return Type: array
    */ 
  async dump() {
    // Serializable representation of keychain
    const obj = {
      salt: this.data.salt,
      iterations: this.data.iterations,
      kvs: this.data.kvs,
      pwCheck: this.data.pwCheck
    };

    const repr = JSON.stringify(obj);
    const checksum = await sha256Base64(repr);

    return [repr, checksum];
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Compute HMAC(domain) as key
    const domainTag = await this._computeDomainTag(name);
    const kvsKey = encodeBuffer(domainTag);
    const rec = this.data.kvs[kvsKey];

    if (!rec) {
      return null;
    }

    const ivBuf = decodeBuffer(rec.iv);
    const ctBuf = decodeBuffer(rec.ct);
    const aad = new Uint8Array(domainTag); // bind ciphertext to domainTag for swap attack defense

    let paddedPlain;
    try {
      paddedPlain = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: ivBuf,
          additionalData: aad,
          tagLength: 128
        },
        this.secrets.aesKey,
        ctBuf
      );
    } catch (e) {
      // If decryption fails, likely tampering or swap attack
      throw new Error("Decryption failed (possible tampering or swap attack)");
    }

    return unpadPassword(paddedPlain);
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
    // Compute padded password to hide its length
    const padded = padPassword(value);

    // Compute domainTag = HMAC(domain)
    const domainTag = await this._computeDomainTag(name);
    const kvsKey = encodeBuffer(domainTag);

    // Generate random IV for AES-GCM
    const iv = getRandomBytes(12); // Uint8Array
    const aad = new Uint8Array(domainTag); // bind ciphertext to the domainTag

    const ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: aad,
        tagLength: 128
      },
      this.secrets.aesKey,
      padded
    );

    // Store encrypted record (Base64 encodings)
    this.data.kvs[kvsKey] = {
      iv: encodeBuffer(iv),
      ct: encodeBuffer(ciphertext)
    };
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
    */
  async remove(name) {
    const domainTag = await this._computeDomainTag(name);
    const kvsKey = encodeBuffer(domainTag);

    if (Object.prototype.hasOwnProperty.call(this.data.kvs, kvsKey)) {
      delete this.data.kvs[kvsKey];
      return true;
    }

    return false;
  }
}

module.exports = { Keychain };
