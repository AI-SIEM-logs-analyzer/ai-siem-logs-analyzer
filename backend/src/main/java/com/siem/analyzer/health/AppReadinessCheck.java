package com.siem.analyzer.health;

import com.siem.analyzer.config.AppConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

/**
 * Reports whether the application is ready to serve traffic.
 *
 * <p>The skeleton has no downstream dependencies yet, so this always reports UP. As PostgreSQL,
 * Kafka and Redis are wired in, their checks belong here — the {@code /q/health/ready} contract
 * stays the same for the orchestrator and for the Compose healthcheck.
 *
 * <p>The response carries the active environment, which makes it easy to tell from the outside
 * which configuration a running instance picked up.
 */
@Readiness
@ApplicationScoped
public class AppReadinessCheck implements HealthCheck {

    static final String NAME = "app-readiness";

    @Inject AppConfig appConfig;

    @Override
    public HealthCheckResponse call() {
        return HealthCheckResponse.named(NAME)
                .up()
                .withData("environment", appConfig.environment())
                .build();
    }
}
