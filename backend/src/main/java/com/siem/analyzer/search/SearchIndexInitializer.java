package com.siem.analyzer.search;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.ResponseException;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.siem.analyzer.config.AppConfig;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.jboss.logging.Logger;

@ApplicationScoped
public class SearchIndexInitializer {

    private static final Logger LOG = Logger.getLogger(SearchIndexInitializer.class);

    private static final String MAPPING_RESOURCE = "opensearch/log-events-mapping.json";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final Rest5Client restClient;
    private final AppConfig appConfig;

    private volatile boolean mappingCurrent;

    @Inject
    public SearchIndexInitializer(Rest5Client restClient, AppConfig appConfig) {
        this.restClient = restClient;
        this.appConfig = appConfig;
    }

    void onStart(@Observes StartupEvent event) {
        try {
            ensureIndex();
        } catch (RuntimeException e) {
            LOG.errorf(
                    e,
                    "Could not prepare the search index '%s'. Search is unavailable until it"
                            + " exists; ingestion is unaffected.",
                    appConfig.search().indexName());
        }
    }

    public void ensureIndex() {
        if (indexExists()) {
            ensureAlias();
            updateMapping(appConfig.search().indexName());
            return;
        }
        createIndex();
        mappingCurrent = true;
        ensureAlias();
        LOG.infof(
                "Created search index '%s' with alias '%s'",
                appConfig.search().indexName(), appConfig.search().alias());
    }

    public boolean mappingCurrent() {
        return mappingCurrent;
    }

    public boolean indexExists() {
        try {
            Response response =
                    restClient.performRequest(
                            new Request("HEAD", "/" + appConfig.search().indexName()));
            return response.getStatusCode() == 200;
        } catch (ResponseException e) {
            throw new SearchUnavailableException("Could not check whether the index exists", e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not reach the search engine", e);
        }
    }

    private void createIndex() {
        Request request = new Request("PUT", "/" + appConfig.search().indexName());
        request.setJsonEntity(readMapping());
        try {
            Response response = restClient.performRequest(request);
            int status = response.getStatusCode();

            if (status == 400) {
                LOG.debugf("Index '%s' already existed", appConfig.search().indexName());
            } else if (status >= 400) {
                throw new SearchUnavailableException(
                        "Could not create the search index: HTTP " + status);
            }
        } catch (ResponseException e) {
            throw new SearchUnavailableException("Could not create the search index", e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not reach the search engine", e);
        }
    }

    private void updateMapping(String index) {
        try {
            Request request = new Request("PUT", "/" + index + "/_mapping");
            request.setJsonEntity(propertiesBody());
            Response response = restClient.performRequest(request);
            int status = response.getStatusCode();
            if (status != 200) {
                mappingCurrent = false;
                LOG.errorf("Could not update the %s mapping: HTTP %d", index, status);
            } else {
                mappingCurrent = true;
                LOG.infof("Mapping of %s is up to date", index);
            }
        } catch (IOException e) {

            mappingCurrent = false;
            LOG.errorf(e, "Could not update the %s mapping", index);
        }
    }

    private String propertiesBody() throws IOException {
        JsonNode properties = JSON.readTree(readMapping()).path("mappings").path("properties");
        return JSON.createObjectNode().set("properties", properties).toString();
    }

    private void ensureAlias() {
        String body =
                """
                {"actions":[{"add":{"index":"%s","alias":"%s"}}]}"""
                        .formatted(appConfig.search().indexName(), appConfig.search().alias());
        Request request = new Request("POST", "/_aliases");
        request.setJsonEntity(body);
        try {
            Response response = restClient.performRequest(request);
            if (response.getStatusCode() >= 400) {
                throw new SearchUnavailableException(
                        "Could not point the alias at the index: HTTP " + response.getStatusCode());
            }
        } catch (ResponseException e) {
            throw new SearchUnavailableException("Could not point the alias at the index", e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not point the alias at the index", e);
        }
    }

    private String readMapping() {
        try (InputStream in =
                Thread.currentThread()
                        .getContextClassLoader()
                        .getResourceAsStream(MAPPING_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Missing classpath resource " + MAPPING_RESOURCE);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read " + MAPPING_RESOURCE, e);
        }
    }
}
