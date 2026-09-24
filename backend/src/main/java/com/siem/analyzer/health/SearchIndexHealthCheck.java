package com.siem.analyzer.health;

import com.siem.analyzer.repo.LogEventIndexStateRepository;
import com.siem.analyzer.search.EventSearch;
import com.siem.analyzer.search.SearchIndexInitializer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

/**
 * Reports the search engine's state and how far the index trails PostgreSQL.
 *
 * <p>Always UP, deliberately. The index is derived: an engine that is down degrades search while
 * ingestion continues, and a check that went DOWN would fail readiness and have the orchestrator
 * pull an instance that is still doing its main job. The state is reported as data so a dashboard
 * or an alert can act on it; {@code quarkus.elasticsearch.health.enabled} is false for the same
 * reason, since the extension's own check does gate readiness.
 *
 * <p>{@code mapping} is {@code outdated} when start-up could not push the mapping's properties onto
 * an existing index; events carrying the new fields are then refused by the index and wait in the
 * backlog until the mapping is repaired.
 */
@Readiness
@ApplicationScoped
public class SearchIndexHealthCheck implements HealthCheck {

    static final String NAME = "search-index";

    @Inject EventSearch search;
    @Inject LogEventIndexStateRepository indexState;
    @Inject SearchIndexInitializer initializer;

    @Override
    @Transactional
    public HealthCheckResponse call() {
        boolean available = search.available();
        long backlog;
        try {
            backlog = indexState.countUnindexed();
        } catch (RuntimeException e) {
            backlog = -1;
        }
        return HealthCheckResponse.named(NAME)
                .up()
                .withData("engine", available ? "up" : "down")
                .withData("backlog", backlog)
                .withData("mapping", initializer.mappingCurrent() ? "current" : "outdated")
                .build();
    }
}
