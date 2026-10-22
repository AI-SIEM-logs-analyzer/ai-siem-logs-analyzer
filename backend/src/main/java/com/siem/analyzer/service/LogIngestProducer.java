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

            LOG.warnf(
                    "Not publishing to logs.ingest: transaction status is %d, not active."
                            + " uploadId=%d, fileName=%s",
                    status, event.uploadId(), event.fileName());
            return;
        }

        transactionRegistry.registerInterposedSynchronization(
                new Synchronization() {
                    @Override
                    public void beforeCompletion() {}

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
