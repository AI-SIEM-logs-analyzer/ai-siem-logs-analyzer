package com.siem.analyzer.enrich;

import java.util.Optional;

public interface UserAgentEnricher {

    Optional<UserAgentEnrichment> classify(String userAgent);
}
