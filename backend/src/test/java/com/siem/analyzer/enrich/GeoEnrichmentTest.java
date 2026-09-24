package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class GeoEnrichmentTest {

    @Test
    void anEnrichmentWithNoValuesIsEmpty() {
        GeoEnrichment geo = new GeoEnrichment(null, null, null, null, null, null, null);

        assertTrue(geo.isEmpty());
    }

    @Test
    void asnAloneIsNotEmpty() {
        GeoEnrichment geo = new GeoEnrichment(null, null, null, null, null, 15169L, "Google LLC");

        assertFalse(geo.isEmpty());
        assertNull(geo.city());
    }

    @Test
    void countryAloneIsNotEmpty() {
        GeoEnrichment geo = new GeoEnrichment("RO", "Romania", null, null, null, null, null);

        assertFalse(geo.isEmpty());
    }
}
