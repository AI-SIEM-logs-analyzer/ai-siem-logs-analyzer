package com.siem.analyzer.service;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.domain.LogIngestEvent;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.security.TestSecurity;
import io.smallrye.reactive.messaging.memory.InMemoryConnector;
import io.smallrye.reactive.messaging.memory.InMemorySink;
import jakarta.enterprise.inject.Any;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Proves the {@code logs.ingest} outgoing channel end to end, minus the broker: the emitter is the
 * production one, the payload is the production serialisation, and only the connector is swapped
 * for the in-memory sink the %test profile configures.
 */
@QuarkusTest
@TestSecurity(user = "ingest-tester", roles = "ANALYST")
class LogIngestProducerTest {

    private static final byte[] LOG_CONTENT =
            "2026-09-07T09:00:00Z INFO firewall denied 10.0.0.9\n".getBytes(StandardCharsets.UTF_8);

    @Inject LogIngestProducer producer;

    @Inject ObjectMapper objectMapper;

    @Inject @Any InMemoryConnector connector;

    private InMemorySink<String> sink;

    @BeforeEach
    void resetSink() {
        sink = connector.sink("logs.ingest");
        sink.clear();
    }

    @Test
    void publishesOneMessagePerEvent() throws Exception {
        LogIngestEvent event = sampleEvent(42L);

        producer.publish(event);

        assertEquals(1, sink.received().size());
        LogIngestEvent sent =
                objectMapper.readValue(sink.received().get(0).getPayload(), LogIngestEvent.class);
        assertEquals(event, sent);
    }

    @Test
    void publishesWhenAnUploadIsAccepted() throws Exception {
        int id =
                given().multiPart("file", "ingest-channel.log", LOG_CONTENT, "text/plain")
                        .formParam("sourceName", "firewall-main")
                        .formParam("sourceType", "FIREWALL")
                        .when()
                        .post("/api/logs/upload")
                        .then()
                        .statusCode(202)
                        .extract()
                        .path("id");

        assertEquals(1, sink.received().size());
        LogIngestEvent sent =
                objectMapper.readValue(sink.received().get(0).getPayload(), LogIngestEvent.class);

        assertEquals(Long.valueOf(id), sent.uploadId());
        assertEquals("ingest-channel.log", sent.fileName());
        assertEquals("firewall-main", sent.sourceName());
        assertEquals("FIREWALL", sent.sourceType());
        assertEquals("ingest-tester", sent.uploadedBy());
        assertEquals(LOG_CONTENT.length, sent.fileSize());
        assertNotNull(sent.checksum());
        assertNotNull(sent.storagePath());
        assertNotNull(sent.uploadedAt());
    }

    @Test
    void holdsTheMessageUntilTheTransactionCommits() {
        LogIngestEvent event = sampleEvent(43L);

        QuarkusTransaction.requiringNew()
                .run(
                        () -> {
                            producer.publish(event);
                            assertTrue(
                                    sink.received().isEmpty(),
                                    "a message must not reach the channel before the transaction"
                                            + " commits");
                        });

        assertEquals(1, sink.received().size());
    }

    @Test
    void publishesNothingWhenTheTransactionRollsBack() {
        LogIngestEvent event = sampleEvent(44L);

        assertThrows(
                IllegalStateException.class,
                () ->
                        QuarkusTransaction.requiringNew()
                                .run(
                                        () -> {
                                            producer.publish(event);
                                            throw new IllegalStateException("persist failed");
                                        }));

        assertTrue(sink.received().isEmpty());
    }

    @Test
    void publishesNothingWhenTheUploadIsRejected() {
        given().multiPart("file", "rejected.exe", LOG_CONTENT, "application/x-msdownload")
                .when()
                .post("/api/logs/upload")
                .then()
                .statusCode(415);

        assertTrue(sink.received().isEmpty());
    }

    private static LogIngestEvent sampleEvent(Long uploadId) {
        return new LogIngestEvent(
                uploadId,
                7L,
                "firewall-main",
                "FIREWALL",
                "sample.log",
                "text/plain",
                123L,
                "abc123",
                "2026/09/07/sample.log",
                "ingest-tester",
                Instant.parse("2026-09-07T09:00:00Z"));
    }
}
