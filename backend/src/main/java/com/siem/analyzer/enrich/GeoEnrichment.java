package com.siem.analyzer.enrich;

public record GeoEnrichment(
        String countryIso,
        String countryName,
        String city,
        Double latitude,
        Double longitude,
        Long asn,
        String asOrg) {

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
