# bash_secrets_saver

Bash library port of `secrets_saver` with default file extension `.ep`.

Because this environment does not include `openssl` and `jq`, this Bash library delegates cryptography and JSON handling to Python while exposing a shell-friendly API.

## Features

- AES-GCM encryption
- PBKDF2-SHA256 key derivation (`600000` iterations)
- One-time key prompt per shell session instance
- Default storage file: `secrets.ep`
- API functions:
  - `ss_init [filename]`
  - `ss_set_secret <key> <value>`
  - `ss_get_secret <key>`
  - `ss_list_secrets`
  - `ss_clear_database`

## Usage

```bash
source ./secrets_saver.sh

# Prompts for the master key when needed.
ss_init "secrets.ep"
ss_set_secret "api_token" "super_secret_value"
ss_get_secret "api_token"
ss_list_secrets
```

## Requirements

- Bash
- Python 3
- Python package `cryptography`
