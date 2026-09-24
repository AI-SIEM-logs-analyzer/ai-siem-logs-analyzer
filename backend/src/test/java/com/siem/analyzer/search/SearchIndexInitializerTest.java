package com.siem.analyzer.search;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.siem.analyzer.config.AppConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

@QuarkusTest
class SearchIndexInitializerTest {

    private static final List<String> GEO_FIELDS =
            List.of(
                    "geo_country_iso",
                    "geo_country_name",
                    "geo_city",
                    "geo_location",
                    "geo_asn",
                    "geo_as_org");

    private static final List<String> USER_AGENT_FIELDS =
            List.of(
                    "ua_browser",
                    "ua_browser_version",
                    "ua_os",
                    "ua_os_version",
                    "ua_device_class",
                    "ua_agent_class",
                    "ua_bot");

    @Inject Rest5Client restClient;
    @Inject AppConfig appConfig;
    @Inject SearchIndexInitializer initializer;
    @Inject ObjectMapper objectMapper;

    @Test
    void createsTheIndexAndPointsTheAliasAtIt() throws IOException {
        JsonNode aliases = get("/" + appConfig.search().alias() + "/_alias");

        assertTrue(aliases.has(appConfig.search().indexName()));
    }

    @Test
    void appliesTheStrictMappingWithTheFieldTypesTheAdrNames() throws IOException {
        JsonNode properties =
                get("/" + appConfig.search().indexName() + "/_mapping")
                        .path(appConfig.search().indexName())
                        .path("mappings")
                        .path("properties");

        assertEquals("wildcard", properties.path("raw").path("type").asText());
        assertEquals("flat_object", properties.path("attributes").path("type").asText());
        assertEquals("ip", properties.path("src_ip").path("type").asText());
        assertTrue(properties.path("src_ip").path("ignore_malformed").asBoolean());
        assertEquals("text", properties.path("message").path("type").asText());
        assertEquals(
                "keyword",
                properties.path("message").path("fields").path("keyword").path("type").asText());
    }

    @Test
    void runningTwiceChangesNothing() throws IOException {
        initializer.ensureIndex();
        JsonNode afterFirstRun = mappingProperties();
        initializer.ensureIndex();

        // No exception is half the assertion: a second create would answer 400
        // resource_already_exists_exception, and a second alias write would fail the same way if
        // it were not written as an idempotent action. The other half is that pushing the mapping
        // onto an index that already carries it leaves the mapping exactly as it was.
        assertTrue(initializer.indexExists());
        assertEquals(afterFirstRun, mappingProperties());
        assertTrue(initializer.mappingCurrent());
    }

    @Test
    void anExistingIndexGainsTheGeoMapping() throws IOException {
        // An index created before the geo fields existed: the real mapping minus every geo_*
        // property, so the test tracks the resource rather than a hand-written copy of it.
        ObjectNode oldMapping = mappingResource();
        ObjectNode oldProperties = (ObjectNode) oldMapping.path("mappings").path("properties");
        oldProperties.remove(GEO_FIELDS);

        try {
            recreateIndexWith(oldMapping);
            assertTrue(mappingProperties().path("geo_country_iso").isMissingNode());

            initializer.ensureIndex();

            JsonNode properties = mappingProperties();
            assertEquals("keyword", properties.path("geo_country_iso").path("type").asText());
            assertEquals("keyword", properties.path("geo_country_name").path("type").asText());
            assertEquals("keyword", properties.path("geo_city").path("type").asText());
            assertEquals("geo_point", properties.path("geo_location").path("type").asText());
            assertEquals("long", properties.path("geo_asn").path("type").asText());
            assertEquals("keyword", properties.path("geo_as_org").path("type").asText());
            // Every property of the resource, by type: OpenSearch echoes some defaults back
            // (doc_values on the wildcard field), so the node as a whole is not byte-for-byte the
            // resource.
            mappingResource()
                    .path("mappings")
                    .path("properties")
                    .properties()
                    .forEach(
                            field ->
                                    assertEquals(
                                            field.getValue().path("type").asText(),
                                            properties.path(field.getKey()).path("type").asText(),
                                            field.getKey()));
            assertTrue(
                    get("/" + appConfig.search().alias() + "/_alias")
                            .has(appConfig.search().indexName()));
            assertTrue(initializer.mappingCurrent());
        } finally {
            restoreFullIndex();
        }
    }

    @Test
    void anExistingIndexGainsTheUserAgentMapping() throws IOException {
        // An index created before the User-Agent fields existed, but already carrying geo.
        ObjectNode oldMapping = mappingResource();
        ((ObjectNode) oldMapping.path("mappings").path("properties")).remove(USER_AGENT_FIELDS);

        try {
            recreateIndexWith(oldMapping);
            assertTrue(mappingProperties().path("ua_browser").isMissingNode());

            initializer.ensureIndex();

            JsonNode properties = mappingProperties();
            for (String field : USER_AGENT_FIELDS) {
                String expected = "ua_bot".equals(field) ? "boolean" : "keyword";
                assertEquals(expected, properties.path(field).path("type").asText(), field);
            }
            assertTrue(initializer.mappingCurrent());
        } finally {
            restoreFullIndex();
        }
    }

    @Test
    void aRefusedMappingUpdateIsReportedAsOutdatedWithoutGatingReadiness() throws IOException {
        // OpenSearch refuses to change the type of a field an index already maps, so an index
        // holding geo_asn as a keyword makes the update fail for real, with no fake server.
        ObjectNode conflicting = mappingResource();
        ((ObjectNode) conflicting.path("mappings").path("properties"))
                .putObject("geo_asn")
                .put("type", "keyword");
        try {
            recreateIndexWith(conflicting);
            initializer.ensureIndex();

            assertFalse(initializer.mappingCurrent());
            given().when()
                    .get("/q/health/ready")
                    .then()
                    .statusCode(200)
                    .body("status", is("UP"))
                    .body("checks.find { it.name == 'search-index' }.status", is("UP"))
                    .body("checks.find { it.name == 'search-index' }.data.mapping", is("outdated"));
        } finally {
            restoreFullIndex();
        }
        assertTrue(initializer.mappingCurrent());
    }

    /**
     * Leaves the shared Dev Services index as every other test expects it: freshly created from the
     * full mapping and aliased. Called from a {@code finally}, so a test that fails between
     * recreating the index with an altered mapping and its last assertion still restores it.
     */
    private void restoreFullIndex() throws IOException {
        restClient.performRequest(new Request("DELETE", "/" + appConfig.search().indexName()));
        initializer.ensureIndex();
    }

    private void recreateIndexWith(ObjectNode mapping) throws IOException {
        String index = appConfig.search().indexName();
        restClient.performRequest(new Request("DELETE", "/" + index));
        Request create = new Request("PUT", "/" + index);
        create.setJsonEntity(objectMapper.writeValueAsString(mapping));
        Response response = restClient.performRequest(create);
        assertEquals(200, response.getStatusCode());
    }

    private ObjectNode mappingResource() throws IOException {
        try (InputStream in =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResourceAsStream("opensearch/log-events-mapping.json")) {
            return (ObjectNode) objectMapper.readTree(in);
        }
    }

    private JsonNode mappingProperties() throws IOException {
        String index = appConfig.search().indexName();
        return get("/" + index + "/_mapping").path(index).path("mappings").path("properties");
    }

    private JsonNode get(String endpoint) throws IOException {
        Response response = restClient.performRequest(new Request("GET", endpoint));
        assertEquals(200, response.getStatusCode());
        return objectMapper.readTree(response.getEntity().getContent());
    }
}
