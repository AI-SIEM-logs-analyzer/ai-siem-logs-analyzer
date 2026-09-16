package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

@QuarkusTest
class SearchBackfillJobTest {

    @Inject SearchBackfillJob job;
    @Inject RecordingEventSearch search;

    @Test
    void aRunWithAnEmptyBacklogDoesNothing() {
        search.reset();

        job.run();

        assertTrue(search.indexed().isEmpty());
    }

    @Test
    void aRunSurvivesAnEngineThatIsDown() {
        search.reset();
        search.failNextWrites(true);

        job.run();

        // The scheduler must keep firing. A job that propagates is a job that stops being
        // scheduled once the engine has an outage — exactly when the backlog needs draining.
        assertFalse(search.available());
    }
}
