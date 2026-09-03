package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LogStorageServiceTest {

    @TempDir Path tempDir;

    private LogStorageService storageService;

    @BeforeEach
    void setUp() {
        storageService = new LogStorageService(tempDir);
    }

    @Test
    void storesInputStreamAndComputesChecksum() throws IOException, NoSuchAlgorithmException {
        byte[] content =
                "2026-09-03T12:00:00Z INFO user logged in\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream in = new ByteArrayInputStream(content);

        LogStorageService.StoredFile stored =
                storageService.store(in, "test-auth.log", "text/plain");

        assertNotNull(stored.storagePath());
        assertTrue(Files.exists(Path.of(stored.storagePath())));
        assertEquals(content.length, stored.size());
        assertEquals("test-auth.log", stored.originalFileName());
        assertEquals("text/plain", stored.contentType());

        // Verify SHA-256 matches
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String expectedChecksum = HexFormat.of().formatHex(digest.digest(content));
        assertEquals(expectedChecksum, stored.checksum());

        // Verify stored file content matches
        byte[] readBack = Files.readAllBytes(Path.of(stored.storagePath()));
        assertEquals(
                new String(content, StandardCharsets.UTF_8),
                new String(readBack, StandardCharsets.UTF_8));
    }

    @Test
    void rejectsEmptyInputStream() {
        ByteArrayInputStream empty = new ByteArrayInputStream(new byte[0]);
        assertThrows(
                IllegalArgumentException.class,
                () -> storageService.store(empty, "empty.log", "text/plain"));
    }

    @Test
    void sanitizesFileName() {
        byte[] content = "some log line\n".getBytes(StandardCharsets.UTF_8);
        ByteArrayInputStream in = new ByteArrayInputStream(content);

        LogStorageService.StoredFile stored =
                storageService.store(in, "../../etc/passwd", "text/plain");

        assertFalse(stored.storagePath().contains(".."));
        assertTrue(Files.exists(Path.of(stored.storagePath())));
    }
}
