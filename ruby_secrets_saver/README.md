# ruby_secrets_saver

Ruby port of the Python `secrets_saver` library.

## Features

- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation (`600000` iterations)
- Default file extension `.ep`
- Prompt-based master key handling (no hardcoded key in examples)
- Optional database adapter support
- API methods:
  - `set_secret`
  - `get_secret`
  - `list_secrets`
  - `clear_database`

## Usage

```ruby
require_relative "lib/secrets_saver"

# Prompts for the master key on first read/write.
saver = SecretsSaver::SecretsSaver.new_file("secrets.ep")
saver.set_secret("api_token", "super_secret_value")

puts saver.get_secret("api_token")
p saver.list_secrets
```

## Test Script

```bash
ruby test/test_secrets_saver.rb
```

For non-interactive runs, provide `SS_MASTER_KEY` as an environment variable at runtime.
