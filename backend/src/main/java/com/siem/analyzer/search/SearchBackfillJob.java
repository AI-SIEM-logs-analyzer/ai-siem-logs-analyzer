package com.siem.analyzer.search;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.scheduler.Scheduled;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

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

            LOG.errorf(e, "Search backfill run failed; the next run will retry");
        }
    }
}
