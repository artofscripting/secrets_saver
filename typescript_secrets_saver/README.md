# typescript_secrets_saver

TypeScript port of the Python `secrets_saver` library.

## Features

- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- Default file extension `.ep`
- Prompt-based master key handling
- Optional database adapter support
- API methods:
  - `setSecret`
  - `getSecret`
  - `listSecrets`
  - `clearDatabase`

## Install

```bash
npm install
npm run build
```

## Usage

```ts
import { SecretsSaver } from "./src/index";

async function main(): Promise<void> {
  // Prompts for the master key on first read/write.
  const saver = await SecretsSaver.create({ filename: "secrets.ep" });
  await saver.setSecret("api_token", "super_secret_value");

  console.log(await saver.getSecret("api_token"));
  console.log(await saver.listSecrets());
}

main().catch(console.error);
```

## Tests

```bash
npm run build
npm test
```

For non-interactive test runs, use prompt overrides in tests or pass values at runtime.
