package com.siem.analyzer.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import io.smallrye.common.annotation.Blocking;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import org.eclipse.microprofile.reactive.messaging.Incoming;
import org.jboss.logging.Logger;

/**
 * Consumes log ingestion events from the {@code logs.ingest} Kafka topic and hands each stored file
 * to the parser.
 *
 * <p>The incoming channel is named {@code logs.ingest-in} rather than {@code logs.ingest}: SmallRye
 * wires an {@code @Outgoing} channel straight into an {@code @Incoming} one of the same name inside
 * the same application, which would route {@link LogIngestProducer} past the broker entirely. Both
 * channels are configured on the one {@code logs.ingest} topic instead.
 *
 * <p>Every message is acknowledged, including the ones that fail. A batch that cannot be handled
 * says so on its own row — {@code FAILED} with the reason — and that row is what the listing
 * endpoint already shows; redelivering it would only repeat a failure the payload guarantees. What
 * the broker retries is the message this consumer never got to acknowledge, which is the case a
 * retry can actually fix.
 */
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

    /**
     * Claims the upload the message names and parses its file.
     *
     * <p>Runs on a worker thread: the status transitions and the parsing are blocking database and
     * file work, which must not run on the event loop. The method holds no transaction of its own —
     * each transition is a short transaction inside {@link LogUploadService}, so a long parse does
     * not hold one open.
     */
    @Incoming("logs.ingest-in")
    @Blocking
    public void consume(String payload) {
        LogIngestEvent event;
        try {
            event = objectMapper.readValue(payload, LogIngestEvent.class);
        } catch (Exception e) {
            // Nothing in the payload identifies a row to mark, so the log is the only record.
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
            // A redelivery, or a second worker that lost the race. The run that claimed the batch
            // owns it; parsing it again would duplicate its events.
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

    /**
     * Writes the failure onto the upload row.
     *
     * <p>A parser that already moved the batch to a terminal status leaves nothing to record here,
     * so that transition is refused and logged rather than propagated: the message has been
     * handled, and failing this method would only nack a batch whose outcome is already stored.
     */
    private void recordFailure(LogIngestEvent event, RuntimeException cause) {
        try {
            uploadService.markFailed(event.uploadId(), String.valueOf(cause.getMessage()));
        } catch (RuntimeException e) {
            LOG.errorf(
                    e, "Could not record the ingestion failure on uploadId=%d", event.uploadId());
        }
    }
}
