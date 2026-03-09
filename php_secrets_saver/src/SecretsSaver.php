<?php

declare(strict_types=1);

namespace SecretsSaver;

use RuntimeException;

interface DatabaseAdapter
{
    public function readEncryptedRow(): ?array;
    public function upsertEncryptedRow(array $content): void;
}

final class InvalidKeyOrCorruptedDataException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('Invalid key or corrupted data.');
    }
}

final class SecretsSaver
{
    private const DEFAULT_FILENAME = 'secrets.ep';
    private const PBKDF2_ITERS = 600000;
    private const KEY_LEN = 32;
    private const SALT_LEN = 16;
    private const NONCE_LEN = 12;
    private const TAG_LEN = 16;

    private string $filename;
    private ?DatabaseAdapter $dbAdapter;
    private $prompt;

    private ?string $key = null;
    private ?array $data = null;

    private function __construct(string $filename, ?DatabaseAdapter $dbAdapter = null, ?callable $prompt = null)
    {
        $this->filename = $filename === '' ? self::DEFAULT_FILENAME : $filename;
        $this->dbAdapter = $dbAdapter;
        $this->prompt = $prompt ?? static fn(string $location): string => self::defaultPrompt($location);

        if (!$this->exists()) {
            $this->getKey();
            $this->data = [];
            $this->save();
        }
    }

    public static function newFile(string $filename = self::DEFAULT_FILENAME, ?callable $prompt = null): self
    {
        return new self($filename, null, $prompt);
    }

    public static function newDatabase(DatabaseAdapter $adapter, ?callable $prompt = null): self
    {
        return new self(self::DEFAULT_FILENAME, $adapter, $prompt);
    }

    public function setSecret(string $key, string $value): void
    {
        $this->ensureLoaded();
        $this->data[$key] = $value;
        $this->save();
    }

    public function getSecret(string $key): ?string
    {
        $this->ensureLoaded();
        return $this->data[$key] ?? null;
    }

    public function listSecrets(): array
    {
        $this->ensureLoaded();
        $keys = array_keys($this->data);
        sort($keys, SORT_STRING);
        return $keys;
    }

    public function clearDatabase(): void
    {
        $this->data = [];
        $this->save();
    }

    private function exists(): bool
    {
        if ($this->dbAdapter !== null) {
            return $this->dbAdapter->readEncryptedRow() !== null;
        }
        return is_file($this->filename);
    }

    private function getKey(): string
    {
        if ($this->key !== null) {
            return $this->key;
        }

        $location = $this->dbAdapter !== null ? 'database' : $this->filename;
        $prompt = $this->prompt;
        $this->key = (string)$prompt($location);
        return $this->key;
    }

    private function deriveKey(string $password, string $salt): string
    {
        return hash_pbkdf2('sha256', $password, $salt, self::PBKDF2_ITERS, self::KEY_LEN, true);
    }

    private function loadRaw(): array
    {
        if ($this->dbAdapter !== null) {
            $row = $this->dbAdapter->readEncryptedRow();
            if ($row === null) {
                throw new RuntimeException('Secrets not found in database.');
            }
            return $row;
        }

        $raw = file_get_contents($this->filename);
        if ($raw === false) {
            throw new RuntimeException('Unable to read secrets file.');
        }
        $content = json_decode($raw, true);
        if (!is_array($content)) {
            throw new RuntimeException('Invalid payload format.');
        }
        return $content;
    }

    private function saveRaw(array $content): void
    {
        if ($this->dbAdapter !== null) {
            $this->dbAdapter->upsertEncryptedRow($content);
            return;
        }

        $json = json_encode($content, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('Unable to encode encrypted payload.');
        }

        if (file_put_contents($this->filename, $json) === false) {
            throw new RuntimeException('Unable to write secrets file.');
        }
    }

    private function load(): void
    {
        $content = $this->loadRaw();

        $salt = base64_decode((string)$content['salt'], true);
        $nonce = base64_decode((string)$content['nonce'], true);
        $ciphertextPlusTag = base64_decode((string)$content['ciphertext'], true);
        if ($salt === false || $nonce === false || $ciphertextPlusTag === false || strlen($ciphertextPlusTag) < self::TAG_LEN) {
            throw new RuntimeException('Invalid payload encoding.');
        }

        $ciphertext = substr($ciphertextPlusTag, 0, -self::TAG_LEN);
        $tag = substr($ciphertextPlusTag, -self::TAG_LEN);

        $key = $this->deriveKey($this->getKey(), $salt);
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            ''
        );

        if ($plaintext === false) {
            $this->key = null;
            throw new InvalidKeyOrCorruptedDataException();
        }

        $parsed = json_decode($plaintext, true);
        if (!is_array($parsed)) {
            throw new RuntimeException('Invalid decrypted payload.');
        }

        $this->data = $parsed;
    }

    private function ensureLoaded(): void
    {
        if ($this->data !== null) {
            return;
        }

        if ($this->exists()) {
            $this->load();
        } else {
            $this->data = [];
        }
    }

    private function save(): void
    {
        $this->ensureLoaded();

        $salt = random_bytes(self::SALT_LEN);
        $nonce = random_bytes(self::NONCE_LEN);
        $key = $this->deriveKey($this->getKey(), $salt);

        $plaintext = json_encode($this->data, JSON_UNESCAPED_SLASHES);
        if ($plaintext === false) {
            throw new RuntimeException('Unable to encode plaintext payload.');
        }

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed.');
        }

        $this->saveRaw([
            'salt' => base64_encode($salt),
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertext . $tag),
        ]);
    }

    private static function defaultPrompt(string $location): string
    {
        if (function_exists('readline')) {
            $line = readline("Enter key for {$location}: ");
            return $line === false ? '' : trim($line);
        }

        fwrite(STDOUT, "Enter key for {$location}: ");
        $line = fgets(STDIN);
        return $line === false ? '' : trim($line);
    }
}
