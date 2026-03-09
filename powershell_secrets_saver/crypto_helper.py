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


def encrypt(password_b64: str, plaintext_json: str) -> str:
    password = base64.b64decode(password_b64)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)

    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext_json.encode("utf-8"), None)

    out = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }
    return json.dumps(out, separators=(",", ":"))


def decrypt(password_b64: str, salt_b64: str, nonce_b64: str, ciphertext_b64: str) -> str:
    password = base64.b64decode(password_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    key = derive_key(password, salt)
    aes = AESGCM(key)
    try:
        plaintext = aes.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        print("Invalid key or corrupted data.", file=sys.stderr)
        raise SystemExit(2)

    return plaintext.decode("utf-8")


def main() -> int:
    if len(sys.argv) < 2:
        print("missing command", file=sys.stderr)
        return 1

    cmd = sys.argv[1]

    if cmd == "encrypt":
        if len(sys.argv) != 4:
            print("usage: encrypt <password_b64> <plaintext_json>", file=sys.stderr)
            return 1
        print(encrypt(sys.argv[2], sys.argv[3]))
        return 0

    if cmd == "decrypt":
        if len(sys.argv) != 6:
            print("usage: decrypt <password_b64> <salt_b64> <nonce_b64> <ciphertext_b64>", file=sys.stderr)
            return 1
        print(decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
        return 0

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
