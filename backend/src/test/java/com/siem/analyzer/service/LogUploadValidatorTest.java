package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.ws.rs.BadRequestException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LogUploadValidatorTest {

    private static final long MAX_SIZE = 1024;
    private static final int SNIFF_BYTES = 512;

    @TempDir Path tempDir;

    private LogUploadValidator validator;

    @BeforeEach
    void setUp() {
        validator =
                new LogUploadValidator(
                        MAX_SIZE,
                        List.of("log", "txt", "json", "ndjson", "csv"),
                        List.of("text/plain", "application/json", "text/csv"),
                        SNIFF_BYTES);
    }

    @Test
    void acceptsPlainTextLogFile() throws IOException {
        Path file =
                write(
                        "auth.log",
                        "2026-09-04T12:00:00Z INFO user logged in\n"
                                .getBytes(StandardCharsets.UTF_8));

        validator.validate(file, "auth.log", "text/plain");
    }

    @Test
    void acceptsFileWhoseExtensionDiffersInCase() throws IOException {
        Path file = write("AUTH.LOG", "some log line\n".getBytes(StandardCharsets.UTF_8));

        validator.validate(file, "AUTH.LOG", "text/plain");
    }

    @Test
    void rejectsEmptyFile() throws IOException {
        Path file = write("empty.log", new byte[0]);

        assertThrows(
                BadRequestException.class,
                () -> validator.validate(file, "empty.log", "text/plain"));
    }

    @Test
    void rejectsFileLargerThanConfiguredLimit() throws IOException {
        Path file = write("big.log", new byte[(int) MAX_SIZE + 1]);

        PayloadTooLargeException e =
                assertThrows(
                        PayloadTooLargeException.class,
                        () -> validator.validate(file, "big.log", "text/plain"));
        assertEquals(MAX_SIZE, e.getMaxSizeBytes());
    }

    @Test
    void rejectsDisallowedExtension() throws IOException {
        Path file =
                write(
                        "payload.exe",
                        "MZ is not what makes this fail\n".getBytes(StandardCharsets.UTF_8));

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "payload.exe", "text/plain"));
    }

    @Test
    void rejectsFileWithNoExtension() throws IOException {
        Path file = write("logfile", "some log line\n".getBytes(StandardCharsets.UTF_8));

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "logfile", "text/plain"));
    }

    @Test
    void rejectsDisallowedContentType() throws IOException {
        Path file = write("report.log", "some log line\n".getBytes(StandardCharsets.UTF_8));

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "report.log", "application/pdf"));
    }

    @Test
    void acceptsContentTypeCarryingCharsetParameter() throws IOException {
        Path file = write("auth.log", "some log line\n".getBytes(StandardCharsets.UTF_8));

        validator.validate(file, "auth.log", "text/plain; charset=UTF-8");
    }

    @Test
    void rejectsGzipContentDisguisedAsLog() throws IOException {
        byte[] gzip = {0x1f, (byte) 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04};
        Path file = write("archive.log", gzip);

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "archive.log", "text/plain"));
    }

    @Test
    void rejectsElfBinaryDisguisedAsLog() throws IOException {
        byte[] elf = {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00};
        Path file = write("tool.log", elf);

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "tool.log", "text/plain"));
    }

    @Test
    void rejectsContentCarryingNulBytes() throws IOException {
        byte[] withNul = {'l', 'o', 'g', 0x00, 'l', 'i', 'n', 'e'};
        Path file = write("binary.log", withNul);

        assertThrows(
                UnsupportedLogFileException.class,
                () -> validator.validate(file, "binary.log", "text/plain"));
    }

    @Test
    void ignoresBinaryContentBeyondTheSniffWindow() throws IOException {
        // Only the first sniffBytes are read, so a NUL past that window is not seen. The test
        // pins that boundary so a change to the window size is a deliberate one.
        byte[] content = new byte[SNIFF_BYTES + 8];
        java.util.Arrays.fill(content, 0, SNIFF_BYTES, (byte) 'a');
        content[SNIFF_BYTES + 1] = 0x00;
        Path file = write("late.log", content);

        validator.validate(file, "late.log", "text/plain");
    }

    private Path write(String name, byte[] content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.write(file, content);
        return file;
    }
}
