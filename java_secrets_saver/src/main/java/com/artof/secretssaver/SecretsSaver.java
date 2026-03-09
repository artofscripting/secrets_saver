package com.artof.secretssaver;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class SecretsSaver {
    private static final String DEFAULT_FILENAME = "secrets.ep";
    private static final int PBKDF2_ITERS = 600_000;
    private static final int KEY_LEN_BITS = 256;
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final Path filename;
    private final DatabaseAdapter dbAdapter;
    private final PromptFunction promptFunction;

    private byte[] key;
    private Map<String, String> data;

    private SecretsSaver(Path filename, DatabaseAdapter dbAdapter, PromptFunction promptFunction) throws Exception {
        this.filename = filename;
        this.dbAdapter = dbAdapter;
        this.promptFunction = promptFunction;
        initializeIfMissing();
    }

    public static SecretsSaver newFile(String filename) throws Exception {
        Path filePath = Path.of(filename == null || filename.isBlank() ? DEFAULT_FILENAME : filename);
        return new SecretsSaver(filePath, null, SecretsSaver::defaultPrompt);
    }

    public static SecretsSaver newFile(String filename, PromptFunction promptFunction) throws Exception {
        Path filePath = Path.of(filename == null || filename.isBlank() ? DEFAULT_FILENAME : filename);
        return new SecretsSaver(filePath, null, promptFunction);
    }

    public static SecretsSaver newDatabase(DatabaseAdapter adapter) throws Exception {
        return new SecretsSaver(Path.of(DEFAULT_FILENAME), adapter, SecretsSaver::defaultPrompt);
    }

    public static SecretsSaver newDatabase(DatabaseAdapter adapter, PromptFunction promptFunction) throws Exception {
        return new SecretsSaver(Path.of(DEFAULT_FILENAME), adapter, promptFunction);
    }

    public synchronized void setSecret(String key, String value) throws Exception {
        ensureLoaded();
        data.put(key, value);
        save();
    }

    public synchronized String getSecret(String key) throws Exception {
        ensureLoaded();
        return data.get(key);
    }

    public synchronized List<String> listSecrets() throws Exception {
        ensureLoaded();
        List<String> keys = new ArrayList<>(data.keySet());
        Collections.sort(keys);
        return keys;
    }

    public synchronized void clearDatabase() throws Exception {
        data = new HashMap<>();
        save();
    }

    private void initializeIfMissing() throws Exception {
        if (!exists()) {
            getKey();
            data = new HashMap<>();
            save();
        }
    }

    private boolean exists() throws Exception {
        if (dbAdapter != null) {
            return dbAdapter.readEncryptedRow() != null;
        }
        return Files.exists(filename);
    }

    private byte[] getKey() throws Exception {
        if (key == null) {
            String location = dbAdapter != null ? "database" : filename.toString();
            String passphrase = promptFunction.prompt(location);
            key = passphrase.getBytes(StandardCharsets.UTF_8);
        }
        return key;
    }

    private byte[] deriveKey(byte[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(
                new String(password, StandardCharsets.UTF_8).toCharArray(),
                salt,
                PBKDF2_ITERS,
                KEY_LEN_BITS
        );
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    private RawContent loadRaw() throws Exception {
        if (dbAdapter != null) {
            RawContent row = dbAdapter.readEncryptedRow();
            if (row == null) {
                throw new IOException("Secrets not found in database.");
            }
            return row;
        }

        String text = Files.readString(filename, StandardCharsets.UTF_8);
        return OBJECT_MAPPER.readValue(text, RawContent.class);
    }

    private void saveRaw(RawContent content) throws Exception {
        if (dbAdapter != null) {
            dbAdapter.upsertEncryptedRow(content);
            return;
        }

        String serialized = OBJECT_MAPPER.writeValueAsString(content);
        Files.writeString(filename, serialized, StandardCharsets.UTF_8);
    }

    private void load() throws Exception {
        RawContent content = loadRaw();

        byte[] salt = Base64.getDecoder().decode(content.salt);
        byte[] nonce = Base64.getDecoder().decode(content.nonce);
        byte[] ciphertextAndTag = Base64.getDecoder().decode(content.ciphertext);

        byte[] masterKey = getKey();
        byte[] derivedKey = deriveKey(masterKey, salt);

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(derivedKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] plaintext = cipher.doFinal(ciphertextAndTag);
            data = OBJECT_MAPPER.readValue(plaintext, new TypeReference<>() {});
        } catch (GeneralSecurityException e) {
            key = null;
            throw new InvalidKeyOrCorruptedDataException();
        }
    }

    private void ensureLoaded() throws Exception {
        if (data != null) {
            return;
        }

        if (exists()) {
            load();
        } else {
            data = new HashMap<>();
        }
    }

    private void save() throws Exception {
        ensureLoaded();

        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(nonce);

        byte[] masterKey = getKey();
        byte[] derivedKey = deriveKey(masterKey, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivedKey, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));

        byte[] plaintext = OBJECT_MAPPER.writeValueAsBytes(data);
        byte[] ciphertextAndTag = cipher.doFinal(plaintext);

        RawContent content = new RawContent(
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(nonce),
                Base64.getEncoder().encodeToString(ciphertextAndTag)
        );
        saveRaw(content);
    }

    private static String defaultPrompt(String location) {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword("Enter key for %s: ", location);
            return chars == null ? "" : new String(chars);
        }

        System.out.print("Enter key for " + location + ": ");
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }
}

