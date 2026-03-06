# Secrets Saver

A lightweight, FIPS 140-2/3 compliant Python library for securely storing and managing secrets.

`SecretsSaver` encrypts your data using AES-GCM and derives keys using PBKDF2HMAC (with SHA-256), provided by the standard `cryptography` library. It guarantees that users or applications are only prompted for the encryption/decryption key exactly once per instantiation.

It supports storing your encrypted secrets in:
*   A local file (JSON based)
*   A PostgreSQL database
*   A Microsoft SQL Server (MSSQL) database

## Features

- **FIPS Compliant Cryptography**: Uses AES-GCM for authenticated encryption and PBKDF2 with SHA-256 for secure key derivation.
- **One-Time Prompting**: Automatically prompts for the master key securely using `getpass` exactly once per instance via standard input (safely hiding the password).
- **Flexible Storage**: Works cleanly offline with local files but seamlessly transitions to PostgreSQL or MSSQL without changing how you interact with your secrets.
- **Simple API**: Easy to use dictionary-like interface masked behind `set_secret` and `get_secret`.

## Installation

You will need the `cryptography` library. If you intend to use the database features, you will also need `SQLAlchemy` and the respective database drivers.

```bash
# For local file storage only
pip install cryptography

# For PostgreSQL support
pip install cryptography sqlalchemy psycopg2-binary

# For Microsoft SQL Server support
pip install cryptography sqlalchemy pyodbc
```

## Usage

### 1. Local File Storage (Default)

```python
from secrets_saver import SecretsSaver

# Will prompt for a key if secrets.db doesn't exist or upon first access
db = SecretsSaver("secrets.db")

# Store a secret
db.set_secret("api_token", "super_secret_value")

# Retrieve a secret
token = db.get_secret("api_token")
print(f"Retrieved token: {token}")

# List all stored keys
print(db.list_secrets())
```

### 2. PostgreSQL Storage

Pass a standard SQLAlchemy connection string via `db_url`.

```python
from secrets_saver import SecretsSaver

db_url = "postgresql+psycopg2://admin:password@localhost:5432/my_database"
db = SecretsSaver(db_url=db_url)

db.set_secret("db_password", "my_postgres_secret")
print(db.get_secret("db_password"))
```

### 3. Microsoft SQL Server (MSSQL) Storage

Pass the MSSQL connection string. Be sure the ODBC driver specified matches what is installed on your system.

```python
from secrets_saver import SecretsSaver

db_url = "mssql+pyodbc://admin:password@localhost/my_database?driver=ODBC+Driver+17+for+SQL+Server"
db = SecretsSaver(db_url=db_url)

db.set_secret("api_key", "my_mssql_secret")
print(db.get_secret("api_key"))
```

## API Reference

### `SecretsSaver(filename="secrets.db", db_url=None)`
Initializes the class. If `db_url` is provided, it attempts to connect to the SQL database using SQLAlchemy, automatically creating an `encrypted_secrets` table if it does not exist. Otherwise, it defaults to the local file `filename`.

*   **`set_secret(key: str, value: str)`**: Encrypts and saves a key-value pair to the database.
*   **`get_secret(key: str) -> str`**: Decrypts and retrieves the value for the given key. Returns `None` if the key does not exist.
*   **`list_secrets() -> list`**: Returns a list of all secret keys stored.
*   **`clear_database()`**: Deletes all secrets in the current database/file and overwrites the storage with an empty encrypted payload.
