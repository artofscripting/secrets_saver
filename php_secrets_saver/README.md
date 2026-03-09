# php_secrets_saver

PHP port of the Python `secrets_saver` library.

## Features

- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- Default file extension `.ep`
- Prompt-based master key handling (no hardcoded key in examples)
- Optional database adapter support
- API methods:
  - `setSecret`
  - `getSecret`
  - `listSecrets`
  - `clearDatabase`

## Usage

```php
<?php
require __DIR__ . '/src/SecretsSaver.php';

use SecretsSaver\SecretsSaver;

// Prompts for the master key on first read/write.
$saver = SecretsSaver::newFile('secrets.ep');
$saver->setSecret('api_token', 'super_secret_value');

echo $saver->getSecret('api_token') . PHP_EOL;
print_r($saver->listSecrets());
```

## Test Script

```bash
php test.php
```

For non-interactive runs, provide `SS_MASTER_KEY` as an environment variable at runtime.
