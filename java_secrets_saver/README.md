# secrets-saver-java

Java port of the Python `secrets_saver` library.

## Features

- AES-GCM encryption (AES-256-GCM)
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- File backend by default
- Optional database backend via adapter interface
- Equivalent API methods:
  - `setSecret`
  - `getSecret`
  - `listSecrets`
  - `clearDatabase`

## Build

```bash
mvn test
```

## Quick Example

```java
// Prompts for the master key on first read/write.
SecretsSaver saver = SecretsSaver.newFile("secrets.ep");
saver.setSecret("api_token", "super_secret");
String value = saver.getSecret("api_token");
```

