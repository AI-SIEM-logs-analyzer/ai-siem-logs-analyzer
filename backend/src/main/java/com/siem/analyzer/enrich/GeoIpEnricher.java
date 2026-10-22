package com.siem.analyzer.enrich;

import java.util.Optional;

public interface GeoIpEnricher {

    Optional<GeoEnrichment> lookup(String ip);
}
