const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const fs = require("node:fs");

const { SecretsSaver, InvalidKeyOrCorruptedDataError } = require("./index");

function fixedPrompt(password) {
  return async () => password;
}

function testPasswords() {
  const base = crypto.randomBytes(16).toString("hex");
  return { good: base, bad: `${base}-wrong` };
}

test("set/get/list/clear on file backend", async () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), "tmp-secrets-"));
  const file = path.join(dir, "secrets.ep");
  const { good } = testPasswords();

  const db = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(good) });

  await db.setSecret("a", "1");
  await db.setSecret("b", "2");

  const value = await db.getSecret("a");
  assert.equal(value, "1");

  const keys = await db.listSecrets();
  assert.deepEqual(keys.sort(), ["a", "b"]);

  await db.clearDatabase();
  assert.deepEqual(await db.listSecrets(), []);
});

test("invalid key raises expected error", async () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), "tmp-secrets-"));
  const file = path.join(dir, "secrets.ep");
  const { good, bad } = testPasswords();

  const writer = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(good) });
  await writer.setSecret("x", "y");

  const reader = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(bad) });

  await assert.rejects(async () => {
    await reader.getSecret("x");
  }, InvalidKeyOrCorruptedDataError);
});

