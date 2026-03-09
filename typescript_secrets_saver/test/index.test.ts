import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { SecretsSaver, InvalidKeyOrCorruptedDataError, type PromptFn } from "../src/index";

function fixedPrompt(password: string): PromptFn {
  return async () => password;
}

function testPasswords(): { good: string; bad: string } {
  const good = crypto.randomBytes(16).toString("hex");
  return { good, bad: `${good}-wrong` };
}

test("set/get/list/clear file backend", async () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), "tmp-secrets-ts-"));
  const file = path.join(dir, "secrets.ep");
  const { good } = testPasswords();

  const saver = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(good) });
  await saver.setSecret("a", "1");
  await saver.setSecret("b", "2");

  assert.equal(await saver.getSecret("a"), "1");
  assert.deepEqual(await saver.listSecrets(), ["a", "b"]);

  await saver.clearDatabase();
  assert.deepEqual(await saver.listSecrets(), []);
});

test("invalid key raises expected error", async () => {
  const dir = fs.mkdtempSync(path.join(process.cwd(), "tmp-secrets-ts-"));
  const file = path.join(dir, "secrets.ep");
  const { good, bad } = testPasswords();

  const writer = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(good) });
  await writer.setSecret("x", "y");

  const reader = await SecretsSaver.create({ filename: file, prompt: fixedPrompt(bad) });

  await assert.rejects(
    async () => {
      await reader.getSecret("x");
    },
    InvalidKeyOrCorruptedDataError
  );
});
