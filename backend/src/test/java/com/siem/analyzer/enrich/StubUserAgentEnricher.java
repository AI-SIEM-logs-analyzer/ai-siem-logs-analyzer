package com.siem.analyzer.enrich;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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
