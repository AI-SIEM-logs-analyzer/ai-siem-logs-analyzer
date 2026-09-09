package com.siem.analyzer.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Status;
import jakarta.transaction.Synchronization;
import jakarta.transaction.TransactionSynchronizationRegistry;
import org.eclipse.microprofile.reactive.messaging.Channel;
import org.eclipse.microprofile.reactive.messaging.Emitter;
import org.jboss.logging.Logger;

/**
 * Publishes log ingestion events to the {@code logs.ingest} Kafka channel.
 *
 * <p>A message is emitted only once the transaction that produced it has committed. The consumer of
 * this channel reads the {@code log_upload} row the event names, so an event sent from inside a
 * transaction that then rolls back would point at a row that never existed. The payload is still
 * serialised eagerly, inside the caller's transaction: a value this producer cannot serialise is a
 * fault of the work in progress, and it belongs with the rollback rather than after it.
 */
@ApplicationScoped
public class LogIngestProducer {

    private static final Logger LOG = Logger.getLogger(LogIngestProducer.class);

    private final Emitter<String> emitter;
    private final ObjectMapper objectMapper;
    private final TransactionSynchronizationRegistry transactionRegistry;

    @Inject
    public LogIngestProducer(
            @Channel("logs.ingest") Emitter<String> emitter,
            ObjectMapper objectMapper,
            TransactionSynchronizationRegistry transactionRegistry) {
        this.emitter = emitter;
        this.objectMapper = objectMapper;
        this.transactionRegistry = transactionRegistry;
    }

    /**
     * Serializes the event and sends it to the Kafka channel once the current transaction commits.
     *
     * <p>Called with no transaction in progress, it sends immediately.
     *
     * @throws IllegalStateException the event cannot be serialized
     */
    public void publish(LogIngestEvent event) {
        String json;
        try {
            json = objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize LogIngestEvent", e);
        }

        int status = transactionRegistry.getTransactionStatus();
        if (status == Status.STATUS_NO_TRANSACTION) {
            send(json, event);
            return;
        }
        if (status != Status.STATUS_ACTIVE) {
            // Already rolling back or already completing: there is no commit left to wait for, and
            // registering a synchronization at this point would itself fail.
            LOG.warnf(
                    "Not publishing to logs.ingest: transaction status is %d, not active."
                            + " uploadId=%d, fileName=%s",
                    status, event.uploadId(), event.fileName());
            return;
        }

        transactionRegistry.registerInterposedSynchronization(
                new Synchronization() {
                    @Override
                    public void beforeCompletion() {
                        // Nothing to do: the send belongs after the commit, not before it.
                    }

                    @Override
                    public void afterCompletion(int completionStatus) {
                        if (completionStatus != Status.STATUS_COMMITTED) {
                            LOG.warnf(
                                    "Transaction rolled back, dropping logs.ingest event:"
                                            + " uploadId=%d, fileName=%s",
                                    event.uploadId(), event.fileName());
                            return;
                        }
                        send(json, event);
                    }
                });
    }

    /**
     * Emits the payload and reports the outcome.
     *
     * <p>After the commit there is no caller left to receive a failure — the upload has already
     * been answered — so a broker that refuses the message is logged at error level instead. The
     * row stays {@code PENDING}, which is what a later reconciliation looks for.
     */
    private void send(String json, LogIngestEvent event) {
        try {
            emitter.send(json)
                    .whenComplete(
                            (ignored, failure) -> {
                                if (failure != null) {
                                    LOG.errorf(
                                            failure,
                                            "Failed to publish to logs.ingest, upload stays"
                                                    + " PENDING: uploadId=%d, fileName=%s",
                                            event.uploadId(),
                                            event.fileName());
                                } else {
                                    LOG.infof(
                                            "Published log ingest event to logs.ingest:"
                                                    + " uploadId=%d, fileName=%s",
                                            event.uploadId(), event.fileName());
                                }
                            });
        } catch (RuntimeException e) {
            LOG.errorf(
                    e,
                    "Failed to publish to logs.ingest, upload stays PENDING: uploadId=%d,"
                            + " fileName=%s",
                    event.uploadId(),
                    event.fileName());
        }
    }
}
