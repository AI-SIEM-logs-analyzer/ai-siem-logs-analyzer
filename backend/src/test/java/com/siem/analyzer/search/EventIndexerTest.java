package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.LogEventIndexStateRepository;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@QuarkusTest
class EventIndexerTest {

    @Inject EventIndexer indexer;
    @Inject RecordingEventSearch search;
    @Inject LogEventIndexStateRepository indexState;
    @Inject LogEventRepository events;
    @Inject LogSourceRepository sourceRepository;

    @BeforeEach
    void reset() {
        search.reset();
    }

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
    void indexesAnEventAndRecordsThatItDid() {
        LogEvent event = persistEvent("indexed now");

        int written = indexer.indexNow(List.of(event));

        assertEquals(1, written);
        assertEquals(
                List.of(event.getId()),
                search.indexed().stream().map(IndexableEvent::eventId).toList());
        assertTrue(indexState.listUnindexed(10).isEmpty());
    }

    @Test
    @TestTransaction
    void leavesTheEventInTheBacklogWhenTheEngineRefuses() {
        LogEvent event = persistEvent("engine down");
        search.failNextWrites(true);

        int written = indexer.indexNow(List.of(event));

        assertEquals(0, written);
        assertEquals(
                List.of(event.getId()),
                indexState.listUnindexed(10).stream().map(LogEvent::getId).toList());
    }

    @Test
    @TestTransaction
    void doesNotPropagateAnEngineFailureToItsCaller() {
        persistEvent("engine down");
        search.failNextWrites(true);

        // No assertion of exception thrown: an ingestion path that fails because search is down
        // would trade a stale index for lost data, which is the whole point of the derived design.
        assertEquals(0, indexer.indexNow(List.of(persistEvent("another"))));
    }

    @Test
    @TestTransaction
    void indexesNothingForAnEmptyBatch() {
        assertEquals(0, indexer.indexNow(List.of()));
        assertTrue(search.indexed().isEmpty());
    }

    @Test
    @TestTransaction
    void drainsOnlyWhatIsStillMissing() {
        LogEvent first = persistEvent("first");
        LogEvent second = persistEvent("second");
        indexer.indexNow(List.of(first));
        search.reset();

        int drained = indexer.drainBacklog(100);

        assertEquals(1, drained);
        assertEquals(
                List.of(second.getId()),
                search.indexed().stream().map(IndexableEvent::eventId).toList());
    }
}
