package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

@QuarkusTest
class OpenSearchEventSearchIndexTest {

    @Inject OpenSearchEventSearch search;
    @Inject Rest5Client restClient;
    @Inject AppConfig appConfig;
    @Inject ObjectMapper objectMapper;

    @Test
    void storesAnEventUnderItsOwnIdentifier() throws IOException {
        search.index(List.of(event(9001L, "first write", Map.of())));
        refresh();

        JsonNode document = document(9001L);

        assertTrue(document.path("found").asBoolean());
        assertEquals(9001L, document.path("_source").path("event_id").asLong());
        assertEquals("first write", document.path("_source").path("message").asText());
        assertEquals("ERROR", document.path("_source").path("severity").asText());
    }

    @Test
    void indexingTheSameEventTwiceLeavesOneDocument() throws IOException {
        search.index(List.of(event(9002L, "first", Map.of())));
        search.index(List.of(event(9002L, "second", Map.of())));
        refresh();

        JsonNode document = document(9002L);

        assertEquals("second", document.path("_source").path("message").asText());
    }

    @Test
    void keepsAnEventWhoseAddressIsNotAnAddress() throws IOException {
        search.index(List.of(event(9003L, "bad address", Map.of("srcIp", "not-an-ip"))));
        refresh();

        assertTrue(document(9003L).path("found").asBoolean());
    }

    @Test
    void storesUnplacedKeysWithoutGrowingTheMapping() throws IOException {
        search.index(
                List.of(
                        event(
                                9004L,
                                "with attributes",
                                Map.of("attributes", Map.of("tenant", "acme")))));
        refresh();

        JsonNode mapping =
                json("GET", "/" + appConfig.search().indexName() + "/_mapping")
                        .path(appConfig.search().indexName())
                        .path("mappings")
                        .path("properties");

        assertTrue(document(9004L).path("found").asBoolean());
        assertFalse(mapping.has("tenant"));
    }

    @Test
    void anEnrichedEventKeepsItsGeoFieldsInTheDocument() throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("geoCountryIso", "US");
        payload.put("geoCountryName", "United States");
        payload.put("geoCity", "Mountain View");
        payload.put("geoAsn", 15169);
        payload.put("geoAsOrg", "Google LLC");
        payload.put("geoLocation", Map.of("lat", 37.386, "lon", -122.084));
        search.index(List.of(event(9005L, "enriched", payload)));
        refresh();

        JsonNode source = document(9005L).path("_source");

        assertEquals("US", source.path("geo_country_iso").asText());
        assertEquals("Mountain View", source.path("geo_city").asText());
        assertEquals(15169L, source.path("geo_asn").asLong());
        assertEquals(37.386, source.path("geo_location").path("lat").asDouble(), 0.001);
    }

    @Test
    void anEventWithoutGeoDataWritesNoGeoFields() throws IOException {
        search.index(List.of(event(9006L, "not enriched", Map.of())));
        refresh();

        JsonNode source = document(9006L).path("_source");

        assertFalse(source.has("geo_country_iso"));
        assertFalse(source.has("geo_location"));
    }

    @Test
    void aClassifiedEventKeepsItsUserAgentFieldsInTheDocument() throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userAgent", "curl/8.4.0");
        payload.put("uaBrowser", "Curl");
        payload.put("uaBrowserVersion", "8.4.0");
        payload.put("uaDeviceClass", "Robot");
        payload.put("uaAgentClass", "Robot");
        payload.put("uaBot", true);
        search.index(List.of(event(9007L, "classified", payload)));
        refresh();

        JsonNode source = document(9007L).path("_source");

        assertEquals("Curl", source.path("ua_browser").asText());
        assertEquals("8.4.0", source.path("ua_browser_version").asText());
        assertEquals("Robot", source.path("ua_device_class").asText());
        assertTrue(source.path("ua_bot").isBoolean());
        assertTrue(source.path("ua_bot").booleanValue());
        assertFalse(source.has("ua_os"));
    }

    @Test
    void anEventWithoutUserAgentDataWritesNoUserAgentFields() throws IOException {
        search.index(List.of(event(9008L, "not classified", Map.of())));
        refresh();

        JsonNode source = document(9008L).path("_source");

        assertFalse(source.has("ua_browser"));
        assertFalse(source.has("ua_bot"));
    }

    @Test
    void reportsTheEngineAsAvailable() {
        assertTrue(search.available());
    }

    @Test
    void refusesABatchWithNoEventsQuietly() {
        search.index(List.of());
        // No request is made at all; reaching here is the assertion.
    }

    private IndexableEvent event(long id, String message, Map<String, Object> payload) {
        return new IndexableEvent.Builder()
                .eventId(id)
                .sourceId(1L)
                .occurredAt(Instant.parse("2026-09-01T10:00:00Z"))
                .ingestedAt(Instant.parse("2026-09-01T10:00:05Z"))
                .severity(Severity.ERROR)
                .message(message)
                .raw("raw " + message)
                .payload(payload)
                .build();
    }

    private JsonNode document(long id) throws IOException {
        return json("GET", "/" + appConfig.search().alias() + "/_doc/" + id);
    }

    private void refresh() throws IOException {
        restClient.performRequest(
                new Request("POST", "/" + appConfig.search().alias() + "/_refresh"));
    }

    private JsonNode json(String method, String endpoint) throws IOException {
        Response response = restClient.performRequest(new Request(method, endpoint));
        return objectMapper.readTree(response.getEntity().getContent());
    }
}
