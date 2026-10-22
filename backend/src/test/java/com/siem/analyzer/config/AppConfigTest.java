package com.siem.analyzer.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.parse.JsonFieldMapping;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Duration;
import org.junit.jupiter.api.Test;

@QuarkusTest
class AppConfigTest {

    @Inject AppConfig appConfig;

    @Test
    void environmentComesFromTheActiveProfile() {
        assertEquals("test", appConfig.environment());
    }

    @Test
    void aiApiKeyResolvesWithoutAnExternalSecret() {

        assertFalse(appConfig.ai().apiKey().isBlank());
    }

    @Test
    void jsonFieldMappingInApplicationYamlMatchesTheParserDefaults() {

        assertEquals(
                JsonFieldMapping.defaults(),
                JsonFieldMapping.from(appConfig.parse().json().fields()));
    }

    @Test
    void searchDefaultsAreTheDocumentedOnes() {
        AppConfig.Search search = appConfig.search();

        assertEquals("log-events-v1", search.indexName());
        assertEquals("log-events", search.alias());
        assertEquals(500, search.bulkSize());
        assertEquals(Duration.ofSeconds(10), search.queryTimeout());
        assertTrue(search.backfill().enabled());
        assertEquals(Duration.ofSeconds(30), search.backfill().interval());
        assertEquals(1000, search.backfill().batchSize());
    }

    @Test
    void geoipDefaultsAreTheDocumentedOnes() {
        AppConfig.Geoip geoip = appConfig.geoip();

        assertEquals("/opt/geoip/GeoLite2-City.mmdb", geoip.cityDatabasePath());
        assertEquals("/opt/geoip/GeoLite2-ASN.mmdb", geoip.asnDatabasePath());
        assertTrue(geoip.skippedNetworks().contains("10.0.0.0/8"));
        assertTrue(geoip.skippedNetworks().contains("127.0.0.0/8"));
        assertTrue(geoip.skippedNetworks().contains("fc00::/7"));
    }

    @Test
    void geoipIsDisabledUnderTest() {
        assertFalse(appConfig.geoip().enabled());
    }

    @Test
    void userAgentDefaultsAreTheDocumentedOnes() {
        assertEquals(10000, appConfig.userAgent().cacheSize());
    }

    @Test
    void userAgentClassificationIsDisabledUnderTest() {
        assertFalse(appConfig.userAgent().enabled());
    }
}
