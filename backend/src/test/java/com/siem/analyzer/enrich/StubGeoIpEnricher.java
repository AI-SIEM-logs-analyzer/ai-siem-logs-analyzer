package com.siem.analyzer.enrich;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link GeoIpEnricher} CDI substitute that answers from a fixed table, so parser tests stay
 * deterministic without a real GeoLite2 database.
 *
 * <p>Modelled on {@code RecordingEventSearch}: it is an application-scoped bean, so its answers are
 * shared state that a test configures before parsing and must clear afterward via {@link #reset()}.
 */
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
