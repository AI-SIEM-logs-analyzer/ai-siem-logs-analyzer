package com.siem.analyzer.enrich;

import java.util.Optional;

/**
 * The application's view of GeoIP enrichment. An empty result means "no geo data for this address",
 * whatever the reason: a private address, an address the databases do not know, a malformed
 * address, or enrichment switched off. Callers never distinguish those cases, so no caller has to
 * handle a database being absent.
 */
public interface GeoIpEnricher {

    /**
     * Looks up one address.
     *
     * @param ip a literal IPv4 or IPv6 address; a host name, a blank value or {@code null} yields
     *     an empty result rather than a DNS lookup
     * @return the geo data, or empty when there is none
     */
    Optional<GeoEnrichment> lookup(String ip);
}
