package com.siem.analyzer.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.reactive.messaging.Channel;
import org.eclipse.microprofile.reactive.messaging.Emitter;
import org.jboss.logging.Logger;

/** Publishes log ingestion events to the {@code logs.ingest} Kafka channel. */
@ApplicationScoped
public class LogIngestProducer {

    private static final Logger LOG = Logger.getLogger(LogIngestProducer.class);

    private final Emitter<String> emitter;
    private final ObjectMapper objectMapper;

    @Inject
    public LogIngestProducer(
            @Channel("logs.ingest") Emitter<String> emitter, ObjectMapper objectMapper) {
        this.emitter = emitter;
        this.objectMapper = objectMapper;
    }

    /** Serializes and sends the event to the Kafka channel. */
    public void publish(LogIngestEvent event) {
        try {
            String json = objectMapper.writeValueAsString(event);
            emitter.send(json);
            LOG.infof(
                    "Published log ingest event to logs.ingest: uploadId=%d, fileName=%s",
                    event.uploadId(), event.fileName());
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize LogIngestEvent", e);
        }
    }
}
