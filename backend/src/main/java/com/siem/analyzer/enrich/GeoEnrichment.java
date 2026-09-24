package com.siem.analyzer.enrich;

/**
 * Geo data for one source address. Every field is optional, because the City and ASN databases are
 * separate and either may miss an address the other knows. A {@code null} field means the databases
 * had nothing, not that the value is unknown-but-present: the caller writes nothing for it.
 */
public record GeoEnrichment(
        String countryIso,
        String countryName,
        String city,
        Double latitude,
        Double longitude,
        Long asn,
        String asOrg) {

    /** True when no field carries a value, so there is nothing to write onto an event. */
    public boolean isEmpty() {
        return countryIso == null
                && countryName == null
                && city == null
                && latitude == null
                && longitude == null
                && asn == null
                && asOrg == null;
    }
}
