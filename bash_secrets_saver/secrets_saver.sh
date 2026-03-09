#!/usr/bin/env bash

# Bash API for encrypted secret storage.
# Crypto/JSON work is delegated to Python to preserve AES-GCM + PBKDF2 behavior.

SS_FILENAME="secrets.ep"
SS_MASTER_KEY=""

ss_init() {
  local filename="${1:-secrets.ep}"
  SS_FILENAME="$filename"

  if [[ ! -f "$SS_FILENAME" ]]; then
    ss__ensure_key
    ss__py init "$SS_FILENAME" "$SS_MASTER_KEY"
  fi
}

ss_set_secret() {
  local key="$1"
  local value="$2"
  if [[ -z "$key" ]]; then
    echo "ss_set_secret: key is required" >&2
    return 1
  fi

  ss__ensure_initialized
  ss__ensure_key
  ss__py set "$SS_FILENAME" "$SS_MASTER_KEY" "$key" "$value"
}

ss_get_secret() {
  local key="$1"
  if [[ -z "$key" ]]; then
    echo "ss_get_secret: key is required" >&2
    return 1
  fi

  ss__ensure_initialized
  ss__ensure_key
  ss__py get "$SS_FILENAME" "$SS_MASTER_KEY" "$key"
}

ss_list_secrets() {
  ss__ensure_initialized
  ss__ensure_key
  ss__py list "$SS_FILENAME" "$SS_MASTER_KEY"
}

ss_clear_database() {
  ss__ensure_initialized
  ss__ensure_key
  ss__py clear "$SS_FILENAME" "$SS_MASTER_KEY"
}

ss__ensure_initialized() {
  if [[ ! -f "$SS_FILENAME" ]]; then
    ss_init "$SS_FILENAME"
  fi
}

ss__ensure_key() {
  if [[ -n "$SS_MASTER_KEY" ]]; then
    return 0
  fi

  local location="$SS_FILENAME"
  read -r -s -p "Enter key for ${location}: " SS_MASTER_KEY
  echo
}

ss__py() {
  python - "$@" <<'PY'
import base64
import json
import os
import sys
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    return kdf.derive(password)


def save_payload(path: str, key: bytes, data: dict) -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    derived = derive_key(key, salt)
    aes = AESGCM(derived)
    plaintext = json.dumps(data).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)

    content = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(content, f)


def load_payload(path: str, key: bytes) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        content = json.load(f)

    salt = base64.b64decode(content["salt"])
    nonce = base64.b64decode(content["nonce"])
    ciphertext = base64.b64decode(content["ciphertext"])

    derived = derive_key(key, salt)
    aes = AESGCM(derived)
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("Invalid key or corrupted data.", file=sys.stderr)
        sys.exit(2)
    return json.loads(plaintext.decode("utf-8"))


def main() -> int:
    if len(sys.argv) < 2:
        print("missing command", file=sys.stderr)
        return 1

    cmd = sys.argv[1]

    if cmd == "init":
        _, _, path, password = sys.argv
        save_payload(path, password.encode("utf-8"), {})
        return 0

    if cmd == "set":
        _, _, path, password, key, value = sys.argv
        data = load_payload(path, password.encode("utf-8"))
        data[key] = value
        save_payload(path, password.encode("utf-8"), data)
        return 0

    if cmd == "get":
        _, _, path, password, key = sys.argv
        data = load_payload(path, password.encode("utf-8"))
        value = data.get(key)
        if value is not None:
            print(value)
        return 0

    if cmd == "list":
        _, _, path, password = sys.argv
        data = load_payload(path, password.encode("utf-8"))
        for key in sorted(data.keys()):
            print(key)
        return 0

    if cmd == "clear":
        _, _, path, password = sys.argv
        save_payload(path, password.encode("utf-8"), {})
        return 0

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
}
