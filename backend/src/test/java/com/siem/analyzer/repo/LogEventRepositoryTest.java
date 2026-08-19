package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.PersistenceException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Persistence behaviour of {@link LogEvent}, including the JSONB payload and the two timestamps.
 */
@QuarkusTest
class LogEventRepositoryTest {

    private static final Instant NOON = Instant.parse("2026-08-18T12:00:00Z");

    @Inject LogEventRepository repository;
    @Inject LogSourceRepository sourceRepository;

    private LogSource persistedSource(String name) {
        LogSource source = new LogSource();
        source.setName(name);
        source.setType(LogSourceType.SYSLOG);
        sourceRepository.persist(source);
        return source;
    }

    private static LogEvent event(LogSource source, Instant occurredAt) {
        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(occurredAt);
        event.setSeverity(Severity.WARNING);
        event.setMessage("Failed password for invalid user admin");
        event.setRaw(
                "Aug 18 12:00:00 host sshd[4242]: Failed password for invalid user admin"
                        + " from 10.0.0.7 port 51234 ssh2");
        return event;
    }

    @Test
    @TestTransaction
    void persistsAndReadsBackEveryColumn() {
        LogSource source = persistedSource("syslog-a");
        LogEvent stored = event(source, NOON);
        stored.setExternalId("kafka-offset-1001");
        stored.setPayload(Map.of("user", "admin", "srcIp", "10.0.0.7", "port", 51234));

        repository.persist(stored);
        repository.flush();
        // Read through a fresh query rather than the persistence context, so the assertions
        // reflect what PostgreSQL actually stored.
        repository.getEntityManager().clear();

        LogEvent found = repository.findById(stored.getId());
        assertEquals(source.getId(), found.getSource().getId());
        assertEquals("kafka-offset-1001", found.getExternalId());
        assertEquals(NOON, found.getOccurredAt());
        assertEquals(Severity.WARNING, found.getSeverity());
        assertTrue(found.getRaw().startsWith("Aug 18 12:00:00 host sshd"));
        assertEquals("admin", found.getPayload().get("user"));
        // Ingestion time is assigned by the application, and is a different instant from the
        // moment the event was reported to have happened.
        assertNotNull(found.getIngestedAt());
    }

    @Test
    @TestTransaction
    void acceptsAnEventWithoutAnExternalIdOrPayload() {
        LogSource source = persistedSource("syslog-b");
        LogEvent stored = event(source, NOON);

        repository.persist(stored);
        repository.flush();

        assertNotNull(stored.getId());
    }

    @Test
    @TestTransaction
    void rejectsADuplicateExternalId() {
        LogSource source = persistedSource("syslog-c");
        LogEvent first = event(source, NOON);
        first.setExternalId("kafka-offset-2002");
        repository.persist(first);
        repository.flush();

        LogEvent replay = event(source, NOON);
        replay.setExternalId("kafka-offset-2002");

        assertThrows(
                PersistenceException.class,
                () -> {
                    repository.persist(replay);
                    repository.flush();
                });
    }

    @Test
    @TestTransaction
    void listsEventsOfOneSourceWithinATimeRange() {
        LogSource wanted = persistedSource("syslog-d");
        LogSource other = persistedSource("syslog-e");

        repository.persist(event(wanted, NOON.minus(2, ChronoUnit.HOURS)));
        repository.persist(event(wanted, NOON));
        repository.persist(event(wanted, NOON.plus(2, ChronoUnit.HOURS)));
        repository.persist(event(other, NOON));
        repository.flush();

        List<LogEvent> found =
                repository.listForSourceBetween(
                        wanted.getId(),
                        NOON.minus(1, ChronoUnit.HOURS),
                        NOON.plus(1, ChronoUnit.HOURS));

        assertEquals(1, found.size());
        assertEquals(NOON, found.get(0).getOccurredAt());
    }
}
