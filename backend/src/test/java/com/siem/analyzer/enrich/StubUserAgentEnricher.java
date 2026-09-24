package com.siem.analyzer.enrich;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link UserAgentEnricher} CDI substitute that answers from a fixed table, so parser tests stay
 * deterministic and no {@code @QuarkusTest} boot pays for building the Yauaa rule engine.
 *
 * <p>Modelled on {@link StubGeoIpEnricher}: it is an application-scoped bean, so its answers are
 * shared state that a test configures before parsing and must clear afterward via {@link #reset()}.
 */
@Mock
@ApplicationScoped
public class StubUserAgentEnricher implements UserAgentEnricher {

    private final Map<String, UserAgentEnrichment> answers = new ConcurrentHashMap<>();

    public StubUserAgentEnricher answer(String userAgent, UserAgentEnrichment enrichment) {
        answers.put(userAgent, enrichment);
        return this;
    }

    @Override
    public Optional<UserAgentEnrichment> classify(String userAgent) {
        return Optional.ofNullable(userAgent).map(answers::get);
    }

    public void reset() {
        answers.clear();
    }
}
