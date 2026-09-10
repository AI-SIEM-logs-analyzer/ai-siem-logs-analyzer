package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.repo.LogUploadRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.reactive.messaging.memory.InMemoryConnector;
import io.smallrye.reactive.messaging.memory.InMemorySource;
import jakarta.enterprise.inject.Any;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proves the {@code logs.ingest-in} incoming channel end to end, minus the broker: the consumer,
 * the deserialisation and the status transitions are the production ones, and only the connector is
 * swapped for the in-memory source the %test profile configures.
 *
 * <p>The in-memory source delivers in order, so a test that needs to observe "nothing happened"
 * sends a second, valid message afterwards and waits for that one instead of sleeping.
 */
@QuarkusTest
class LogIngestConsumerTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    @Inject LogUploadRepository uploadRepository;

    @Inject ObjectMapper objectMapper;

    @Inject RecordingLogFileParser parser;

    @Inject @Any InMemoryConnector connector;

    private InMemorySource<String> source;

    @BeforeEach
    void resetChannel() {
        source = connector.source("logs.ingest-in");
        parser.reset();
    }

    @Test
    void marksTheUploadProcessing() {
        Long uploadId = storeUpload(LogUploadStatus.PENDING);

        source.send(json(event(uploadId)));

        awaitStatus(uploadId, LogUploadStatus.PROCESSING);
        assertNotNull(processingStartedAt(uploadId), "processing_started_at must be stamped");
    }

    @Test
    void handsTheEventToTheParser() {
        Long uploadId = storeUpload(LogUploadStatus.PENDING);
        LogIngestEvent event = event(uploadId);

        source.send(json(event));

        awaitStatus(uploadId, LogUploadStatus.PROCESSING);
        assertEquals(1, parser.received().size());
        assertEquals(event, parser.received().get(0));
    }

    @Test
    void marksTheUploadFailedWhenTheParserThrows() {
        Long uploadId = storeUpload(LogUploadStatus.PENDING);
        parser.failOn(uploadId);

        source.send(json(event(uploadId)));

        awaitStatus(uploadId, LogUploadStatus.FAILED);
        assertNotNull(errorMessage(uploadId), "the failure reason must be recorded on the row");
    }

    @Test
    void keepsConsumingAfterAnInvalidPayload() {
        Long ignored = storeUpload(LogUploadStatus.PENDING);
        Long next = storeUpload(LogUploadStatus.PENDING);

        source.send("this is not json");
        source.send(json(event(next)));

        awaitStatus(next, LogUploadStatus.PROCESSING);
        assertEquals(LogUploadStatus.PENDING, statusOf(ignored));
    }

    @Test
    void keepsConsumingAfterAnUnknownUploadId() {
        Long next = storeUpload(LogUploadStatus.PENDING);

        source.send(json(event(999_999_999L)));
        source.send(json(event(next)));

        awaitStatus(next, LogUploadStatus.PROCESSING);
        assertFalse(parser.sawUpload(999_999_999L), "an upload with no row must not reach parser");
    }

    @Test
    void leavesAnAlreadyProcessingUploadAlone() {
        Long redelivered = storeUpload(LogUploadStatus.PROCESSING);
        Long next = storeUpload(LogUploadStatus.PENDING);

        source.send(json(event(redelivered)));
        source.send(json(event(next)));

        awaitStatus(next, LogUploadStatus.PROCESSING);
        assertEquals(LogUploadStatus.PROCESSING, statusOf(redelivered));
        assertFalse(parser.sawUpload(redelivered), "a redelivered batch must not be parsed twice");
    }

    private Long storeUpload(LogUploadStatus status) {
        return QuarkusTransaction.requiringNew()
                .call(
                        () -> {
                            LogUpload upload = new LogUpload();
                            upload.setFileName("consumer-" + UUID.randomUUID() + ".log");
                            upload.setContentType("text/plain");
                            upload.setFileSize(64L);
                            upload.setChecksumSha256("sha256-" + UUID.randomUUID());
                            upload.setStoragePath("target/test-uploads/" + UUID.randomUUID());
                            upload.setStatus(status);
                            upload.setUploadedBy("ingest-tester");
                            uploadRepository.persist(upload);
                            return upload.getId();
                        });
    }

    private LogIngestEvent event(Long uploadId) {
        return new LogIngestEvent(
                uploadId,
                null,
                "firewall-main",
                "FIREWALL",
                "consumer.log",
                "text/plain",
                64L,
                "abc123",
                "target/test-uploads/consumer.log",
                "ingest-tester",
                Instant.parse("2026-09-09T09:00:00Z"));
    }

    private String json(LogIngestEvent event) {
        try {
            return objectMapper.writeValueAsString(event);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private LogUploadStatus statusOf(Long uploadId) {
        return readUpload(uploadId, LogUpload::getStatus);
    }

    private Instant processingStartedAt(Long uploadId) {
        return readUpload(uploadId, LogUpload::getProcessingStartedAt);
    }

    private String errorMessage(Long uploadId) {
        return readUpload(uploadId, LogUpload::getErrorMessage);
    }

    /**
     * Reads one field of the row in its own transaction, so it sees what the consumer committed.
     */
    private <T> T readUpload(Long uploadId, java.util.function.Function<LogUpload, T> field) {
        return QuarkusTransaction.requiringNew()
                .call(
                        () ->
                                uploadRepository
                                        .findByIdOptional(uploadId)
                                        .map(field)
                                        .orElseThrow(
                                                () ->
                                                        new AssertionError(
                                                                "no upload with id " + uploadId)));
    }

    /** Polls until the row reaches the status, because the consumer runs on its own thread. */
    private void awaitStatus(Long uploadId, LogUploadStatus expected) {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        LogUploadStatus seen = null;
        while (System.nanoTime() < deadline) {
            seen = statusOf(uploadId);
            if (seen == expected) {
                return;
            }
            try {
                Thread.sleep(25);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                fail("interrupted while waiting for status " + expected);
            }
        }
        fail("upload " + uploadId + " stayed " + seen + " instead of reaching " + expected);
    }
}
