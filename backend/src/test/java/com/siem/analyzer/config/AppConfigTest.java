package com.siem.analyzer.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.parse.JsonFieldMapping;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Verifies that the {@code app} configuration tree resolves under the {@code test} profile. */
@QuarkusTest
class AppConfigTest {

    @Inject AppConfig appConfig;

    @Test
    void environmentComesFromTheActiveProfile() {
        assertEquals("test", appConfig.environment());
    }

    @Test
    void aiApiKeyResolvesWithoutAnExternalSecret() {
        // Dev and test carry a placeholder so the build never depends on a real secret;
        // prod deliberately has no value in application.yaml and must get one from the
        // environment.
        assertFalse(appConfig.ai().apiKey().isBlank());
    }

    @Test
    void jsonFieldMappingInApplicationYamlMatchesTheParserDefaults() {
        // application.yaml repeats the defaults for discoverability. The parser's unit tests run
        // against JsonFieldMapping.defaults(), so a drift here would deploy an untested mapping.
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
}
