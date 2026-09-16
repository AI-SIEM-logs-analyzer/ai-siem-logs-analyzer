package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Persistence behaviour of {@link LogEventIndexStateRepository} and the backlog it defines. */
@QuarkusTest
class LogEventIndexStateRepositoryTest {

    @Inject LogEventRepository events;
    @Inject LogSourceRepository sourceRepository;
    @Inject LogEventIndexStateRepository indexState;

    private LogEvent persistEvent(String message) {
        LogSource source = new LogSource();
        source.setName(message);
        source.setType(LogSourceType.SYSLOG);
        sourceRepository.persist(source);

        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(Instant.now());
        event.setSeverity(Severity.WARNING);
        event.setMessage(message);
        event.setRaw(message);
        events.persist(event);
        events.flush();
        return event;
    }

    @Test
    @TestTransaction
    void listsOnlyEventsWithNoStateRow() {
        LogEvent indexed = persistEvent("already in the index");
        LogEvent pending = persistEvent("not yet indexed");
        indexState.markIndexed(List.of(indexed.getId()), Instant.now());

        List<LogEvent> backlog = indexState.listUnindexed(10);

        assertEquals(1, backlog.size());
        assertEquals(pending.getId(), backlog.get(0).getId());
    }

    @Test
    @TestTransaction
    void marksTheSameEventTwiceWithoutFailing() {
        LogEvent event = persistEvent("delivered twice");

        indexState.markIndexed(List.of(event.getId()), Instant.now());
        indexState.markIndexed(List.of(event.getId()), Instant.now());

        assertTrue(indexState.listUnindexed(10).isEmpty());
        assertEquals(0, indexState.countUnindexed());
    }

    @Test
    @TestTransaction
    void returnsTheOldestEventsFirstAndHonoursTheLimit() {
        LogEvent first = persistEvent("first");
        persistEvent("second");
        persistEvent("third");

        List<LogEvent> backlog = indexState.listUnindexed(1);

        assertEquals(1, backlog.size());
        assertEquals(first.getId(), backlog.get(0).getId());
    }

    @Test
    @TestTransaction
    void marksSeveralEventsInOneCallIncludingOneAlreadyMarked() {
        LogEvent alreadyIndexed = persistEvent("already indexed before the batch");
        LogEvent first = persistEvent("first in the batch");
        LogEvent second = persistEvent("second in the batch");
        indexState.markIndexed(List.of(alreadyIndexed.getId()), Instant.now());

        indexState.markIndexed(
                List.of(alreadyIndexed.getId(), first.getId(), second.getId()), Instant.now());

        assertEquals(0, indexState.countUnindexed());
        assertTrue(indexState.listUnindexed(10).isEmpty());
    }

    @Test
    @TestTransaction
    void markingAnEmptyCollectionIsANoOp() {
        persistEvent("stays unindexed");

        indexState.markIndexed(Set.of(), Instant.now());

        assertEquals(1, indexState.countUnindexed());
    }
}
