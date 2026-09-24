package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Verifies that all enrichment fields (geo and User-Agent) are mapped explicitly in the OpenSearch
 * index. The mapping is strict, so an unmapped enrichment field would be rejected or fall into
 * attributes.
 */
class LogEventsMappingTest {

    private static final Map<String, String> GEO_FIELDS =
            Map.of(
                    "geo_country_iso", "keyword",
                    "geo_country_name", "keyword",
                    "geo_city", "keyword",
                    "geo_location", "geo_point",
                    "geo_asn", "long",
                    "geo_as_org", "keyword");

    @Test
    void everyGeoFieldIsMappedExplicitly() throws Exception {
        JsonNode properties = properties();

        GEO_FIELDS.forEach(
                (field, type) -> {
                    JsonNode node = properties.get(field);
                    assertEquals(type, node == null ? null : node.path("type").asText(null), field);
                });
    }

    private static final Map<String, String> USER_AGENT_FIELDS =
            Map.of(
                    "ua_browser", "keyword",
                    "ua_browser_version", "keyword",
                    "ua_os", "keyword",
                    "ua_os_version", "keyword",
                    "ua_device_class", "keyword",
                    "ua_agent_class", "keyword",
                    "ua_bot", "boolean");

    @Test
    void everyUserAgentFieldIsMappedExplicitly() throws Exception {
        JsonNode properties = properties();

        USER_AGENT_FIELDS.forEach(
                (field, type) -> {
                    JsonNode node = properties.get(field);
                    assertEquals(type, node == null ? null : node.path("type").asText(null), field);
                });
    }

    @Test
    void theMappingStaysStrict() throws Exception {
        JsonNode mappings = mappings();

        assertEquals("strict", mappings.path("dynamic").asText());
    }

    private JsonNode properties() throws Exception {
        return mappings().path("properties");
    }

    private JsonNode mappings() throws Exception {
        try (InputStream in =
                getClass()
                        .getClassLoader()
                        .getResourceAsStream("opensearch/log-events-mapping.json")) {
            JsonNode root = new ObjectMapper().readTree(in);
            return root.get("mappings");
        }
    }
}
