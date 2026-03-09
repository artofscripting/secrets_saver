# secrets_saver_js

JavaScript/Node.js port of the Python `secrets_saver` library.

It encrypts a full JSON payload of secrets using AES-256-GCM and derives keys with PBKDF2-SHA256 (600000 iterations).

## Features

- Prompts for a master key once per instance
- File storage out of the box
- Optional SQL storage via adapter callbacks
- Similar API to Python version:
  - `setSecret(key, value)`
  - `getSecret(key)`
  - `listSecrets()`
  - `clearDatabase()`

## Install

```bash
npm install
```

## File Backend Usage

```js
const { SecretsSaver } = require("./index");

async function main() {
  // Prompts for the master key on first read/write.
  const db = await SecretsSaver.create({ filename: "secrets.ep" });
  await db.setSecret("api_token", "super_secret_value");

  const token = await db.getSecret("api_token");
  console.log(token);

  console.log(await db.listSecrets());
}

main().catch(console.error);
```

## SQL Backend Usage (Adapter)

Pass `dbAdapter` with two async methods:

- `readEncryptedRow()` returns `null` or `{ salt, nonce, ciphertext }`
- `upsertEncryptedRow(content)` stores `{ salt, nonce, ciphertext }`

```js
const { SecretsSaver } = require("./index");

const dbAdapter = {
  async readEncryptedRow() {
    // query row with id=1 from encrypted_secrets
    return null;
  },
  async upsertEncryptedRow(content) {
    // upsert row with id=1 into encrypted_secrets
  }
};

async function main() {
  // Prompts for the master key on first read/write.
  const db = await SecretsSaver.create({ dbAdapter });
  await db.setSecret("db_password", "my_secret");
}
```

This mirrors the Python approach of storing a single encrypted payload row.

