package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.config.AppConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import org.junit.jupiter.api.Test;

@QuarkusTest
class SearchIndexInitializerTest {

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
    void runningTwiceChangesNothing() {
        initializer.ensureIndex();
        initializer.ensureIndex();

        // Reaching here without an exception is the assertion: a second create would answer
        // 400 resource_already_exists_exception, and a second alias write would fail the same
        // way if it were not written as an idempotent action.
        assertTrue(initializer.indexExists());
    }

    private JsonNode get(String endpoint) throws IOException {
        Response response = restClient.performRequest(new Request("GET", endpoint));
        return objectMapper.readTree(response.getEntity().getContent());
    }
}
