# secrets_saver_go

A Go library equivalent to the Python `secrets_saver` package.

It stores all secrets as one encrypted JSON payload using:

- AES-GCM for authenticated encryption
- PBKDF2-SHA256 with 600000 iterations for key derivation
- Base64 encoding for persisted `salt`, `nonce`, and `ciphertext`

## Features

- Prompts for the master key once per `SecretsSaver` instance
- Supports local file storage (JSON payload)
- Supports SQL storage using a single-row `encrypted_secrets` table (`id=1`)
- API mirroring the Python package:
  - `SetSecret`
  - `GetSecret`
  - `ListSecrets`
  - `ClearDatabase`

## Install

```bash
go get github.com/artof/secrets_saver_go
```

## File Backend Example

```go
package main

import (
    "fmt"
    "log"

    secretssaver "github.com/artof/secrets_saver_go"
)

func main() {
    // Prompts for the master key on first read/write.
    s, err := secretssaver.NewFile("secrets.ep")
    if err != nil {
        log.Fatal(err)
    }

    if err := s.SetSecret("api_token", "super_secret_value"); err != nil {
        log.Fatal(err)
    }

    token, ok, err := s.GetSecret("api_token")
    if err != nil {
        log.Fatal(err)
    }
    if ok {
        fmt.Println(token)
    }
}
```

## SQL Backend Example

```go
package main

import (
    "database/sql"
    "log"

    _ "github.com/lib/pq"
    secretssaver "github.com/artof/secrets_saver_go"
)

func main() {
    db, err := sql.Open("postgres", "postgres://user:pass@localhost:5432/dbname?sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }

    // Prompts for the master key on first read/write.
    s, err := secretssaver.NewDB(db, "postgres")
    if err != nil {
        log.Fatal(err)
    }

    if err := s.SetSecret("db_password", "my-secret"); err != nil {
        log.Fatal(err)
    }
}
```

Or use a DSN constructor similar to Python's URL-based initialization:

```go
s, err := secretssaver.NewDBFromDSN(
    "postgres",
    "postgres://user:pass@localhost:5432/dbname?sslmode=disable",
    "postgres",
)
```

Dialect values for `NewDB`:

- `postgres` (uses `$1`, `$2`, ... placeholders)
- `mssql` (uses `@p1`, `@p2`, ... placeholders)
- default/other (uses `?` placeholders)

