package com.siem.analyzer.enrich;

import java.util.Optional;

/**
 * The application's view of User-Agent classification. An empty result means "nothing to say about
 * this header", whatever the reason: no header, a {@code "-"} placeholder, a header the rules
 * recognise nothing in, or classification switched off. Callers never distinguish those cases.
 */
public interface UserAgentEnricher {

    /**
     * Classifies one header.
     *
     * @param userAgent the raw User-Agent value; {@code null}, blank and {@code "-"} yield an empty
     *     result
     * @return what the header says, or empty when it says nothing
     */
    Optional<UserAgentEnrichment> classify(String userAgent);
}
