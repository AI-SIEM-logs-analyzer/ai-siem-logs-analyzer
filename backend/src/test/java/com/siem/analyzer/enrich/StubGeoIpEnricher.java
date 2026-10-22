package com.siem.analyzer.enrich;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Mock
@ApplicationScoped
public class StubGeoIpEnricher implements GeoIpEnricher {

    private final Map<String, GeoEnrichment> answers = new ConcurrentHashMap<>();

    public StubGeoIpEnricher answer(String ip, GeoEnrichment enrichment) {
        answers.put(ip, enrichment);
        return this;
    }

    @Override
    public Optional<GeoEnrichment> lookup(String ip) {
        return Optional.ofNullable(ip).map(answers::get);
    }

    public void reset() {
        answers.clear();
    }
}
