package com.siem.analyzer.health;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

/**
 * Reports whether the application is ready to serve traffic.
 *
 * <p>The skeleton has no downstream dependencies yet, so this always reports UP. As PostgreSQL,
 * Kafka and Redis are wired in, their checks belong here — the {@code /q/health/ready} contract
 * stays the same for the orchestrator and for the Compose healthcheck.
 */
@Readiness
@ApplicationScoped
public class AppReadinessCheck implements HealthCheck {

    static final String NAME = "app-readiness";

    @Override
    public HealthCheckResponse call() {
        return HealthCheckResponse.up(NAME);
    }
}
