package com.siem.analyzer.search;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.ResponseException;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
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
 * Creates the index and its alias when they are missing.
 *
 * <p>Runs at start-up and does nothing when the index is already there, so it is safe on every boot
 * and on every replica. It never modifies an existing index: a mapping change means a new {@code
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

    private final Rest5Client restClient;
    private final AppConfig appConfig;

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

    /** Creates the index and alias if they are missing. Does nothing when they are present. */
    public void ensureIndex() {
        if (indexExists()) {
            ensureAlias();
            return;
        }
        createIndex();
        ensureAlias();
        LOG.infof(
                "Created search index '%s' with alias '%s'",
                appConfig.search().indexName(), appConfig.search().alias());
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
