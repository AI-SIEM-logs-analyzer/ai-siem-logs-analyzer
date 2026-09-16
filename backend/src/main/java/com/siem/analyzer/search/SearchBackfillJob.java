package com.siem.analyzer.search;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Drains the events PostgreSQL holds and the index does not.
 *
 * <p>This schedule is the guarantee that an event becomes searchable. Everything else — the
 * after-commit hook, a future parser calling the indexer directly — only shortens the wait.
 *
 * <p>Concurrent execution is skipped rather than queued: a run that is still working owns the same
 * head of the backlog the next one would read, and overlapping runs would index the same events
 * twice for no gain.
 */
@ApplicationScoped
public class SearchBackfillJob {

    private static final Logger LOG = Logger.getLogger(SearchBackfillJob.class);

    private final EventIndexer indexer;
    private final AppConfig appConfig;

    @Inject
    public SearchBackfillJob(EventIndexer indexer, AppConfig appConfig) {
        this.indexer = indexer;
        this.appConfig = appConfig;
    }

    @Scheduled(
            every = "{app.search.backfill.interval}",
            skipExecutionIf = Scheduled.ApplicationNotRunning.class,
            concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    public void run() {
        if (!appConfig.search().backfill().enabled()) {
            return;
        }
        try {
            int indexed = indexer.drainBacklog(appConfig.search().backfill().batchSize());
            if (indexed > 0) {
                LOG.infof("Backfilled %d events into the search index", indexed);
            }
        } catch (RuntimeException e) {
            // Never propagate: an exception out of a scheduled method is the one way to stop
            // the schedule, and the schedule is what recovers from an outage.
            LOG.errorf(e, "Search backfill run failed; the next run will retry");
        }
    }
}
