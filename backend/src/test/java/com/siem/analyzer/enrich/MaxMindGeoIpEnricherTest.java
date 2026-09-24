package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MaxMindGeoIpEnricherTest {

    private static final String CITY_DB =
            Path.of("src/test/resources/geoip/GeoIP2-City-Test.mmdb").toString();
    private static final String ASN_DB =
            Path.of("src/test/resources/geoip/GeoLite2-ASN-Test.mmdb").toString();
    private static final List<String> PRIVATE = List.of("10.0.0.0/8", "127.0.0.0/8");

    // Addresses drawn from maxmind/MaxMind-DB's source-data fixtures (source-data/GeoIP2-City-
    // Test.json and source-data/GeoLite2-ASN-Test.json), and verified against the .mmdb files
    // downloaded into src/test/resources/geoip. 81.2.69.142 sits in the City fixture's
    // "81.2.69.142/27" London, GB entry; 1.0.0.1 sits in the ASN fixture's "1.0.0.0/24" Google
    // entry.
    private static final String FIXTURE_CITY_IP = "81.2.69.142";
    private static final String FIXTURE_ASN_IP = "1.0.0.1";

    private MaxMindGeoIpEnricher enricher;

    @BeforeEach
    void openDatabases() {
        enricher = new MaxMindGeoIpEnricher(true, CITY_DB, ASN_DB, PRIVATE);
        enricher.open();
    }

    @AfterEach
    void closeDatabases() {
        enricher.close();
    }

    @Test
    void aKnownAddressCarriesCountryAndCity() {
        Optional<GeoEnrichment> result = enricher.lookup(FIXTURE_CITY_IP);

        assertTrue(result.isPresent());
        assertEquals("GB", result.get().countryIso());
        assertEquals("London", result.get().city());
        assertNotNull(result.get().latitude());
        assertNotNull(result.get().longitude());
    }

    @Test
    void aKnownAddressCarriesTheAutonomousSystem() {
        Optional<GeoEnrichment> result = enricher.lookup(FIXTURE_ASN_IP);

        assertTrue(result.isPresent());
        assertEquals(15169L, result.get().asn());
        assertEquals("Google Inc.", result.get().asOrg());
    }

    @Test
    void anAddressTheDatabaseDoesNotKnowYieldsNothing() {
        assertTrue(enricher.lookup("203.0.113.7").isEmpty());
    }

    @Test
    void aPrivateAddressIsSkippedBeforeAnyLookup() {
        assertTrue(enricher.lookup("10.1.2.3").isEmpty());
        assertTrue(enricher.lookup("127.0.0.1").isEmpty());
    }

    @Test
    void aMalformedAddressYieldsNothingRatherThanThrowing() {
        assertTrue(enricher.lookup("not-an-ip").isEmpty());
        assertTrue(enricher.lookup("999.999.999.999").isEmpty());
        assertTrue(enricher.lookup("").isEmpty());
        assertTrue(enricher.lookup(null).isEmpty());
    }

    @Test
    void aHostNameIsNeverResolved() {
        assertTrue(enricher.lookup("example.com").isEmpty());
    }

    @Test
    void aDisabledEnricherLooksUpNothing() {
        MaxMindGeoIpEnricher disabled = new MaxMindGeoIpEnricher(false, CITY_DB, ASN_DB, PRIVATE);
        disabled.open();

        assertTrue(disabled.lookup(FIXTURE_CITY_IP).isEmpty());

        disabled.close();
    }

    @Test
    void aMissingDatabaseDisablesEnrichmentOutsideProduction() {
        MaxMindGeoIpEnricher missing =
                new MaxMindGeoIpEnricher(true, "/no/such/city.mmdb", "/no/such/asn.mmdb", PRIVATE);
        missing.open();

        assertTrue(missing.lookup(FIXTURE_CITY_IP).isEmpty());

        missing.close();
    }

    @Test
    void theSameAddressTwiceGivesTheSameAnswer() {
        assertEquals(enricher.lookup(FIXTURE_CITY_IP), enricher.lookup(FIXTURE_CITY_IP));
    }
}
