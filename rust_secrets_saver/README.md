# secrets_saver_rust

Rust library equivalent of the Python `secrets_saver` package.

## Features

- AES-256-GCM encryption
- PBKDF2-SHA256 key derivation (`600000` iterations)
- File backend by default
- Optional database backend via adapter trait
- API equivalent methods:
  - `set_secret`
  - `get_secret`
  - `list_secrets`
  - `clear_database`

## Quick Example

```rust
use secrets_saver_rust::SecretsSaver;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Prompts for the master key on first read/write.
    let mut saver = SecretsSaver::new_file("secrets.ep")?;
    saver.set_secret("api_token", "super_secret")?;

    let value = saver.get_secret("api_token")?;
    println!("{:?}", value);

    Ok(())
}
```

## Optional DB Backend

Implement `DatabaseAdapter` and pass it to `SecretsSaver::new_db(...)`.
The adapter stores one encrypted payload row with fields: `salt`, `nonce`, `ciphertext`.

