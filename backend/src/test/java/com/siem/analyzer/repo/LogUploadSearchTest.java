package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Every case filters on a per-test {@code uploadedBy}, so rows committed by other test classes
 * cannot drift into the assertions.
 */
@QuarkusTest
class LogUploadSearchTest {

    private static final Instant BASE = Instant.parse("2026-09-01T00:00:00Z");

    @Inject LogUploadRepository uploadRepository;

    @Test
    @TestTransaction
    void filtersByStatus() {
        String owner = owner();
        createUpload(owner, "a.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(owner, "b.log", LogUploadStatus.FAILED, LogFormat.PLAIN, BASE);

        List<LogUpload> found =
                uploadRepository.search(
                        new LogUploadRepository.Filter(
                                LogUploadStatus.FAILED, null, owner, null, null),
                        0,
                        10);

        assertEquals(List.of("b.log"), found.stream().map(LogUpload::getFileName).toList());
    }

    @Test
    @TestTransaction
    void filtersByDetectedFormat() {
        String owner = owner();
        createUpload(owner, "a.json", LogUploadStatus.PENDING, LogFormat.JSON, BASE);
        createUpload(owner, "b.log", LogUploadStatus.PENDING, LogFormat.SYSLOG, BASE);

        List<LogUpload> found =
                uploadRepository.search(
                        new LogUploadRepository.Filter(null, LogFormat.JSON, owner, null, null),
                        0,
                        10);

        assertEquals(List.of("a.json"), found.stream().map(LogUpload::getFileName).toList());
    }

    @Test
    @TestTransaction
    void filtersByUploader() {
        String mine = owner();
        String theirs = owner();
        createUpload(mine, "mine.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(theirs, "theirs.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);

        List<LogUpload> found =
                uploadRepository.search(
                        new LogUploadRepository.Filter(null, null, mine, null, null), 0, 10);

        assertEquals(List.of("mine.log"), found.stream().map(LogUpload::getFileName).toList());
    }

    @Test
    @TestTransaction
    void rangeIncludesFromAndExcludesTo() {
        String owner = owner();
        createUpload(
                owner,
                "before.log",
                LogUploadStatus.PENDING,
                LogFormat.PLAIN,
                BASE.minus(1, ChronoUnit.HOURS));
        createUpload(owner, "at-from.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(
                owner,
                "inside.log",
                LogUploadStatus.PENDING,
                LogFormat.PLAIN,
                BASE.plus(1, ChronoUnit.HOURS));
        createUpload(
                owner,
                "at-to.log",
                LogUploadStatus.PENDING,
                LogFormat.PLAIN,
                BASE.plus(2, ChronoUnit.HOURS));

        List<LogUpload> found =
                uploadRepository.search(
                        new LogUploadRepository.Filter(
                                null, null, owner, BASE, BASE.plus(2, ChronoUnit.HOURS)),
                        0,
                        10);

        assertEquals(
                List.of("inside.log", "at-from.log"),
                found.stream().map(LogUpload::getFileName).toList());
    }

    @Test
    @TestTransaction
    void pagesNewestFirst() {
        String owner = owner();
        createUpload(owner, "oldest.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(
                owner,
                "middle.log",
                LogUploadStatus.PENDING,
                LogFormat.PLAIN,
                BASE.plus(1, ChronoUnit.HOURS));
        createUpload(
                owner,
                "newest.log",
                LogUploadStatus.PENDING,
                LogFormat.PLAIN,
                BASE.plus(2, ChronoUnit.HOURS));

        LogUploadRepository.Filter filter =
                new LogUploadRepository.Filter(null, null, owner, null, null);

        List<LogUpload> firstPage = uploadRepository.search(filter, 0, 2);
        List<LogUpload> secondPage = uploadRepository.search(filter, 1, 2);

        assertEquals(
                List.of("newest.log", "middle.log"),
                firstPage.stream().map(LogUpload::getFileName).toList());
        assertEquals(
                List.of("oldest.log"), secondPage.stream().map(LogUpload::getFileName).toList());
    }

    @Test
    @TestTransaction
    void countsEveryMatchRegardlessOfPageSize() {
        String owner = owner();
        createUpload(owner, "a.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(owner, "b.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);
        createUpload(owner, "c.log", LogUploadStatus.INGESTED, LogFormat.PLAIN, BASE);

        LogUploadRepository.Filter filter =
                new LogUploadRepository.Filter(LogUploadStatus.PENDING, null, owner, null, null);

        assertEquals(2L, uploadRepository.count(filter));
        assertEquals(1, uploadRepository.search(filter, 0, 1).size());
    }

    @Test
    @TestTransaction
    void emptyFilterMatchesEverything() {
        String owner = owner();
        createUpload(owner, "a.log", LogUploadStatus.PENDING, LogFormat.PLAIN, BASE);

        long all =
                uploadRepository.count(
                        new LogUploadRepository.Filter(null, null, null, null, null));

        assertTrue(all >= 1L);
    }

    private static String owner() {
        return "owner-" + UUID.randomUUID();
    }

    private void createUpload(
            String uploadedBy,
            String fileName,
            LogUploadStatus status,
            LogFormat format,
            Instant createdAt) {
        LogUpload upload = new LogUpload();
        upload.setFileName(fileName);
        upload.setContentType("text/plain");
        upload.setFileSize(1024L);
        upload.setChecksumSha256("sha256-" + UUID.randomUUID());
        upload.setStoragePath("/tmp/storage/" + fileName);
        upload.setStatus(status);
        upload.setDetectedFormat(format);
        upload.setUploadedBy(uploadedBy);
        upload.setCreatedAt(createdAt);
        uploadRepository.persist(upload);
    }
}
