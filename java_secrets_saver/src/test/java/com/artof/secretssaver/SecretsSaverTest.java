package com.artof.secretssaver;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SecretsSaverTest {

    @Test
    void setGetListClear_fileBackend() throws Exception {
        Path dir = Files.createTempDirectory("secrets-saver-java-");
        Path file = dir.resolve("secrets.ep");
        String pass = "test-" + UUID.randomUUID();

        SecretsSaver saver = SecretsSaver.newFile(file.toString(), location -> pass);

        saver.setSecret("a", "1");
        saver.setSecret("b", "2");

        assertEquals("1", saver.getSecret("a"));

        List<String> keys = saver.listSecrets();
        assertEquals(List.of("a", "b"), keys);

        saver.clearDatabase();
        assertTrue(saver.listSecrets().isEmpty());
    }

    @Test
    void invalidKey_throwsExpectedException() throws Exception {
        Path dir = Files.createTempDirectory("secrets-saver-java-");
        Path file = dir.resolve("secrets.ep");
        String goodPass = "test-" + UUID.randomUUID();
        String badPass = goodPass + "-wrong";

        SecretsSaver writer = SecretsSaver.newFile(file.toString(), location -> goodPass);
        writer.setSecret("x", "y");

        SecretsSaver reader = SecretsSaver.newFile(file.toString(), location -> badPass);

        assertThrows(InvalidKeyOrCorruptedDataException.class, () -> reader.getSecret("x"));
    }
}

