package com.siem.analyzer.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import io.smallrye.common.annotation.Blocking;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import org.eclipse.microprofile.reactive.messaging.Incoming;
import org.jboss.logging.Logger;

@ApplicationScoped
public class LogIngestConsumer {

    private static final Logger LOG = Logger.getLogger(LogIngestConsumer.class);

    private final LogUploadService uploadService;
    private final LogFileParser parser;
    private final ObjectMapper objectMapper;

    @Inject
    public LogIngestConsumer(
            LogUploadService uploadService, LogFileParser parser, ObjectMapper objectMapper) {
        this.uploadService = uploadService;
        this.parser = parser;
        this.objectMapper = objectMapper;
    }

    @Incoming("logs.ingest-in")
    @Blocking
    public void consume(String payload) {
        LogIngestEvent event;
        try {
            event = objectMapper.readValue(payload, LogIngestEvent.class);
        } catch (Exception e) {

            LOG.errorf(e, "Dropping unreadable logs.ingest message: %s", payload);
            return;
        }

        if (event.uploadId() == null) {
            LOG.errorf("Dropping logs.ingest message with no uploadId: %s", payload);
            return;
        }

        try {
            uploadService.markProcessing(event.uploadId());
        } catch (NotFoundException e) {
            LOG.errorf(
                    "Dropping logs.ingest message for an upload that no longer exists: uploadId=%d,"
                            + " fileName=%s",
                    event.uploadId(), event.fileName());
            return;
        } catch (IllegalUploadTransitionException e) {

            LOG.warnf(
                    "Skipping logs.ingest message for an upload already past PENDING: uploadId=%d,"
                            + " status=%s",
                    event.uploadId(), e.getFrom());
            return;
        }

        try {
            parser.parse(event);
        } catch (RuntimeException e) {
            LOG.errorf(e, "Ingestion failed for uploadId=%d", event.uploadId());
            recordFailure(event, e);
        }
    }

    private void recordFailure(LogIngestEvent event, RuntimeException cause) {
        try {
            uploadService.markFailed(event.uploadId(), String.valueOf(cause.getMessage()));
        } catch (RuntimeException e) {
            LOG.errorf(
                    e, "Could not record the ingestion failure on uploadId=%d", event.uploadId());
        }
    }
}
