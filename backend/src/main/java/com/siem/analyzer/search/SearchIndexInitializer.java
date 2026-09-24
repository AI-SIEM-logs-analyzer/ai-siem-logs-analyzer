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

/**
 * Creates the index and its alias when they are missing, and brings an existing index's mapping up
 * to date.
 *
 * <p>Runs at start-up and is idempotent, so it is safe on every boot and on every replica. On an
 * existing index it only ever adds properties: OpenSearch accepts new fields on a mapping but
 * refuses a changed type for a field it already maps. A changed type still means a new {@code
 * app.search.index-name} and an alias moved onto it, which is a deliberate operation rather than
 * something a restart performs silently.
 *
 * <p>A failure here is logged, not thrown. The engine is a derived read path — an application that
 * refuses to start because search is unavailable would stop accepting the uploads that PostgreSQL
 * can still take.
 */
@ApplicationScoped
public class SearchIndexInitializer {

    private static final Logger LOG = Logger.getLogger(SearchIndexInitializer.class);

    private static final String MAPPING_RESOURCE = "opensearch/log-events-mapping.json";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final Rest5Client restClient;
    private final AppConfig appConfig;

    // Read by the readiness check, written by whichever thread last ran ensureIndex().
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

    /**
     * Creates the index and alias if they are missing. When the index is present, points the alias
     * at it and pushes the mapping's properties onto it, so an index created before a field was
     * added to the mapping gains that field instead of refusing every document that carries it.
     */
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

    /** Whether the last run left the index carrying every property of the mapping resource. */
    public boolean mappingCurrent() {
        return mappingCurrent;
    }

    /**
     * Whether the configured index is present.
     *
     * <p>Status is read off the response rather than caught as a {@link ResponseException}: the
     * low-level client only raises that exception for a 5xx (a node failure worth retrying), and
     * treats every other status, 404 included, as a normal answer.
     */
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
            // A 400 here is another replica winning the race; the index it created carries the
            // same mapping. Anything else 4xx is a real problem (a malformed mapping, most
            // likely) and is not swallowed the same way.
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

    /**
     * Pushes the mapping's properties onto an index that already exists. OpenSearch accepts new
     * fields on an existing mapping but refuses a changed type for an existing field, so this is
     * additive by construction.
     *
     * <p>A failure here is logged, not thrown, and shows as {@code mapping: outdated} on the
     * readiness check, which stays UP. Readiness never gates on the search engine. Enriched events
     * would be rejected as {@code strict_dynamic_mapping_exception}, stay in the anti-join backlog
     * and be picked up by {@link SearchBackfillJob} once the mapping is repaired.
     */
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
            // ResponseException (a 5xx) is an IOException, so a node failure lands here too.
            mappingCurrent = false;
            LOG.errorf(e, "Could not update the %s mapping", index);
        }
    }

    /**
     * The body {@code PUT <index>/_mapping} expects: only the {@code properties} object of the
     * mapping resource. Settings cannot change on an open index, and {@code dynamic} is already set
     * by whichever run created it.
     */
    private String propertiesBody() throws IOException {
        JsonNode properties = JSON.readTree(readMapping()).path("mappings").path("properties");
        return JSON.createObjectNode().set("properties", properties).toString();
    }

    /**
     * Points the alias at the index.
     *
     * <p>Written through {@code _aliases} rather than {@code PUT /index/_alias/name} because the
     * actions body is what a rebuild uses to move the alias between two indices atomically, and
     * running the same shape in both places means the rebuild path is exercised on every boot.
     */
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
