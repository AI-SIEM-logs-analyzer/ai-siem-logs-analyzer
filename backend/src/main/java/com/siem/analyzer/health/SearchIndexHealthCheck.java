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
