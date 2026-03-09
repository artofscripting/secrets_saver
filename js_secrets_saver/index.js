const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const readline = require("node:readline/promises");
const { stdin, stdout } = require("node:process");

const DEFAULT_FILENAME = "secrets.ep";
const PBKDF2_ITERS = 600000;
const KEY_LEN = 32;
const SALT_LEN = 16;
const NONCE_LEN = 12;

class InvalidKeyOrCorruptedDataError extends Error {
  constructor() {
    super("Invalid key or corrupted data.");
    this.name = "InvalidKeyOrCorruptedDataError";
  }
}

class SecretsSaver {
  constructor(options = {}) {
    this.filename = options.filename || DEFAULT_FILENAME;
    this.dbAdapter = options.dbAdapter || null;
    this.prompt = options.prompt || defaultPrompt;

    this._key = null;
    this._data = null;
  }

  static async create(options = {}) {
    const instance = new SecretsSaver(options);
    await instance._init();
    return instance;
  }

  async setSecret(key, value) {
    await this._ensureLoaded();
    this._data[key] = value;
    await this._save();
  }

  async getSecret(key) {
    await this._ensureLoaded();
    return this._data[key] ?? null;
  }

  async listSecrets() {
    await this._ensureLoaded();
    return Object.keys(this._data);
  }

  async clearDatabase() {
    this._data = {};
    await this._save();
  }

  async _init() {
    const exists = await this._exists();
    if (!exists) {
      await this._getKey();
      this._data = {};
      await this._save();
    }
  }

  async _exists() {
    if (this.dbAdapter) {
      const row = await this.dbAdapter.readEncryptedRow();
      return !!row;
    }
    return fs.existsSync(this.filename);
  }

  async _getKey() {
    if (this._key) {
      return this._key;
    }

    const location = this.dbAdapter ? "database" : this.filename;
    const password = await this.prompt(location);
    this._key = Buffer.from(password, "utf8");
    return this._key;
  }

  _deriveKey(salt) {
    return crypto.pbkdf2Sync(this._key, salt, PBKDF2_ITERS, KEY_LEN, "sha256");
  }

  async _loadRaw() {
    if (this.dbAdapter) {
      const row = await this.dbAdapter.readEncryptedRow();
      if (!row) {
        throw new Error("Secrets not found in database.");
      }
      return row;
    }

    const raw = await fs.promises.readFile(this.filename, "utf8");
    return JSON.parse(raw);
  }

  async _saveRaw(content) {
    if (this.dbAdapter) {
      await this.dbAdapter.upsertEncryptedRow(content);
      return;
    }

    const target = path.resolve(this.filename);
    await fs.promises.writeFile(target, JSON.stringify(content), { mode: 0o600 });
  }

  async _load() {
    const content = await this._loadRaw();

    const salt = Buffer.from(content.salt, "base64");
    const nonce = Buffer.from(content.nonce, "base64");
    const ciphertext = Buffer.from(content.ciphertext, "base64");

    await this._getKey();
    const key = this._deriveKey(salt);

    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
      const tag = ciphertext.subarray(ciphertext.length - 16);
      const body = ciphertext.subarray(0, ciphertext.length - 16);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
      this._data = JSON.parse(plaintext.toString("utf8"));
    } catch (err) {
      this._key = null;
      throw new InvalidKeyOrCorruptedDataError();
    }
  }

  async _ensureLoaded() {
    if (this._data !== null) {
      return;
    }

    const exists = await this._exists();
    if (exists) {
      await this._load();
    } else {
      this._data = {};
    }
  }

  async _save() {
    await this._ensureLoaded();

    const salt = crypto.randomBytes(SALT_LEN);
    const nonce = crypto.randomBytes(NONCE_LEN);
    await this._getKey();
    const key = this._deriveKey(salt);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    const plaintext = Buffer.from(JSON.stringify(this._data), "utf8");
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const ciphertext = Buffer.concat([encrypted, tag]);

    const content = {
      salt: salt.toString("base64"),
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64")
    };

    await this._saveRaw(content);
  }
}

async function defaultPrompt(location) {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question(`Enter key for ${location}: `);
    return answer;
  } finally {
    rl.close();
  }
}

module.exports = {
  SecretsSaver,
  InvalidKeyOrCorruptedDataError
};

