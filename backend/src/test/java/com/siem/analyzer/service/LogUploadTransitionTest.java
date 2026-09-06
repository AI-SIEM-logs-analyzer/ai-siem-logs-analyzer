package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.repo.LogUploadRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

@QuarkusTest
class LogUploadTransitionTest {

    @Inject LogUploadService uploadService;
    @Inject LogUploadRepository uploadRepository;

    @Test
    @TestTransaction
    void markProcessingMovesPendingUploadAndStampsStartTime() {
        LogUpload upload = createUpload(LogUploadStatus.PENDING);

        LogUpload updated = uploadService.markProcessing(upload.getId());

        assertEquals(LogUploadStatus.PROCESSING, updated.getStatus());
        assertNotNull(updated.getProcessingStartedAt());
        assertNull(updated.getProcessedAt());
    }

    @Test
    @TestTransaction
    void markIngestedRecordsEventCountAndFinishTime() {
        LogUpload upload = createUpload(LogUploadStatus.PROCESSING);

        LogUpload updated = uploadService.markIngested(upload.getId(), 4210L);

        assertEquals(LogUploadStatus.INGESTED, updated.getStatus());
        assertEquals(4210L, updated.getEventCount());
        assertNotNull(updated.getProcessedAt());
        assertNull(updated.getErrorMessage());
    }

    @Test
    @TestTransaction
    void markFailedFromPendingRecordsTheError() {
        LogUpload upload = createUpload(LogUploadStatus.PENDING);

        LogUpload updated = uploadService.markFailed(upload.getId(), "storage unreadable");

        assertEquals(LogUploadStatus.FAILED, updated.getStatus());
        assertEquals("storage unreadable", updated.getErrorMessage());
        assertNotNull(updated.getProcessedAt());
    }

    @Test
    @TestTransaction
    void markFailedFromProcessingRecordsTheError() {
        LogUpload upload = createUpload(LogUploadStatus.PROCESSING);

        LogUpload updated = uploadService.markFailed(upload.getId(), "parse error at line 12");

        assertEquals(LogUploadStatus.FAILED, updated.getStatus());
        assertEquals("parse error at line 12", updated.getErrorMessage());
    }

    @Test
    @TestTransaction
    void markFailedTruncatesAnOversizedErrorMessage() {
        LogUpload upload = createUpload(LogUploadStatus.PROCESSING);

        LogUpload updated = uploadService.markFailed(upload.getId(), "x".repeat(5000));

        assertEquals(LogUploadService.MAX_ERROR_MESSAGE_LENGTH, updated.getErrorMessage().length());
    }

    @Test
    @TestTransaction
    void markIngestedRejectsAnUploadThatWasNeverProcessing() {
        LogUpload upload = createUpload(LogUploadStatus.PENDING);

        assertThrows(
                IllegalUploadTransitionException.class,
                () -> uploadService.markIngested(upload.getId(), 1L));
    }

    @Test
    @TestTransaction
    void markProcessingRejectsAnAlreadyIngestedUpload() {
        LogUpload upload = createUpload(LogUploadStatus.INGESTED);

        assertThrows(
                IllegalUploadTransitionException.class,
                () -> uploadService.markProcessing(upload.getId()));
    }

    @Test
    @TestTransaction
    void markFailedRejectsAnAlreadyFailedUpload() {
        LogUpload upload = createUpload(LogUploadStatus.FAILED);

        assertThrows(
                IllegalUploadTransitionException.class,
                () -> uploadService.markFailed(upload.getId(), "again"));
    }

    @Test
    @TestTransaction
    void transitioningAnUnknownUploadIsNotFound() {
        assertThrows(NotFoundException.class, () -> uploadService.markProcessing(-1L));
    }

    private LogUpload createUpload(LogUploadStatus status) {
        LogUpload upload = new LogUpload();
        upload.setFileName("app.log");
        upload.setContentType("text/plain");
        upload.setFileSize(1024L);
        upload.setChecksumSha256("sha256-" + UUID.randomUUID());
        upload.setStoragePath("/tmp/storage/app.log");
        upload.setStatus(status);
        upload.setUploadedBy("tester");
        upload.setCreatedAt(Instant.now());
        uploadRepository.persist(upload);
        return upload;
    }
}
