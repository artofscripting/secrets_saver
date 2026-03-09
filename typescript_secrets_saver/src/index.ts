import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline/promises";
import { stdin, stdout } from "node:process";

const DEFAULT_FILENAME = "secrets.ep";
const PBKDF2_ITERS = 600000;
const KEY_LEN = 32;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;

export interface RawContent {
  salt: string;
  nonce: string;
  ciphertext: string;
}

export interface DatabaseAdapter {
  readEncryptedRow(): Promise<RawContent | null>;
  upsertEncryptedRow(content: RawContent): Promise<void>;
}

export type PromptFn = (location: string) => Promise<string>;

export class InvalidKeyOrCorruptedDataError extends Error {
  constructor() {
    super("Invalid key or corrupted data.");
    this.name = "InvalidKeyOrCorruptedDataError";
  }
}

export class SecretsSaver {
  private readonly filename: string;
  private readonly dbAdapter: DatabaseAdapter | null;
  private readonly prompt: PromptFn;

  private key: Buffer | null = null;
  private data: Record<string, string> | null = null;

  private constructor(filename: string, dbAdapter: DatabaseAdapter | null, prompt?: PromptFn) {
    this.filename = filename || DEFAULT_FILENAME;
    this.dbAdapter = dbAdapter;
    this.prompt = prompt ?? defaultPrompt;
  }

  static async create(options?: {
    filename?: string;
    dbAdapter?: DatabaseAdapter | null;
    prompt?: PromptFn;
  }): Promise<SecretsSaver> {
    const s = new SecretsSaver(
      options?.filename ?? DEFAULT_FILENAME,
      options?.dbAdapter ?? null,
      options?.prompt
    );

    if (!(await s.exists())) {
      await s.getKey();
      s.data = {};
      await s.save();
    }

    return s;
  }

  async setSecret(key: string, value: string): Promise<void> {
    await this.ensureLoaded();
    this.data![key] = value;
    await this.save();
  }

  async getSecret(key: string): Promise<string | null> {
    await this.ensureLoaded();
    return this.data![key] ?? null;
  }

  async listSecrets(): Promise<string[]> {
    await this.ensureLoaded();
    return Object.keys(this.data!).sort();
  }

  async clearDatabase(): Promise<void> {
    this.data = {};
    await this.save();
  }

  private async exists(): Promise<boolean> {
    if (this.dbAdapter) {
      return (await this.dbAdapter.readEncryptedRow()) !== null;
    }
    return fs.existsSync(this.filename);
  }

  private async getKey(): Promise<Buffer> {
    if (this.key) {
      return this.key;
    }

    const location = this.dbAdapter ? "database" : this.filename;
    const pass = await this.prompt(location);
    this.key = Buffer.from(pass, "utf8");
    return this.key;
  }

  private deriveKey(salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(this.key!, salt, PBKDF2_ITERS, KEY_LEN, "sha256");
  }

  private async loadRaw(): Promise<RawContent> {
    if (this.dbAdapter) {
      const row = await this.dbAdapter.readEncryptedRow();
      if (!row) {
        throw new Error("Secrets not found in database.");
      }
      return row;
    }

    const raw = await fs.promises.readFile(this.filename, "utf8");
    return JSON.parse(raw) as RawContent;
  }

  private async saveRaw(content: RawContent): Promise<void> {
    if (this.dbAdapter) {
      await this.dbAdapter.upsertEncryptedRow(content);
      return;
    }

    const target = path.resolve(this.filename);
    await fs.promises.writeFile(target, JSON.stringify(content), { mode: 0o600 });
  }

  private async load(): Promise<void> {
    const content = await this.loadRaw();

    const salt = Buffer.from(content.salt, "base64");
    const nonce = Buffer.from(content.nonce, "base64");
    const ciphertextPlusTag = Buffer.from(content.ciphertext, "base64");
    if (ciphertextPlusTag.length < TAG_LEN) {
      this.key = null;
      throw new InvalidKeyOrCorruptedDataError();
    }

    const ciphertext = ciphertextPlusTag.subarray(0, ciphertextPlusTag.length - TAG_LEN);
    const tag = ciphertextPlusTag.subarray(ciphertextPlusTag.length - TAG_LEN);

    await this.getKey();
    const derived = this.deriveKey(salt);

    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", derived, nonce);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      this.data = JSON.parse(plaintext.toString("utf8")) as Record<string, string>;
    } catch {
      this.key = null;
      throw new InvalidKeyOrCorruptedDataError();
    }
  }

  private async ensureLoaded(): Promise<void> {
    if (this.data !== null) {
      return;
    }

    if (await this.exists()) {
      await this.load();
    } else {
      this.data = {};
    }
  }

  private async save(): Promise<void> {
    await this.ensureLoaded();

    const salt = crypto.randomBytes(SALT_LEN);
    const nonce = crypto.randomBytes(NONCE_LEN);
    await this.getKey();
    const derived = this.deriveKey(salt);

    const cipher = crypto.createCipheriv("aes-256-gcm", derived, nonce);
    const plaintext = Buffer.from(JSON.stringify(this.data), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    await this.saveRaw({
      salt: salt.toString("base64"),
      nonce: nonce.toString("base64"),
      ciphertext: Buffer.concat([ciphertext, tag]).toString("base64")
    });
  }
}

async function defaultPrompt(location: string): Promise<string> {
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const answer = await rl.question(`Enter key for ${location}: `);
    return answer;
  } finally {
    rl.close();
  }
}
