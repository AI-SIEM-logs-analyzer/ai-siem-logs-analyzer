package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.enrich.GeoEnrichment;
import com.siem.analyzer.enrich.StubGeoIpEnricher;
import com.siem.analyzer.repo.LogSourceRepository;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.service.DefaultLogFileParser;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * End-to-end integration test verifying that parsed log events are indexed into the search store
 * and become searchable immediately after parsing.
 */
@QuarkusTest
class ParsedEventSearchIntegrationTest {

    @Inject DefaultLogFileParser parser;
    @Inject EventSearch search;
    @Inject RecordingEventSearch recordingSearch;
    @Inject StubGeoIpEnricher stubGeoIpEnricher;
    @Inject Rest5Client restClient;
    @Inject AppConfig appConfig;
    @Inject SearchIndexInitializer initializer;
    @Inject LogUploadRepository uploadRepository;
    @Inject LogSourceRepository sourceRepository;

    @TempDir Path tempDir;

    private LogSource source;

    @BeforeEach
    void setUp() throws IOException {
        recordingSearch.setDelegateToReal(true);
        try {
            restClient.performRequest(new Request("DELETE", "/" + appConfig.search().indexName()));
        } catch (Exception ignored) {
        }
        initializer.ensureIndex();

        source =
                QuarkusTransaction.requiringNew()
                        .call(
                                () -> {
                                    String name = "search-source-" + UUID.randomUUID();
                                    LogSource s = new LogSource();
                                    s.setName(name);
                                    s.setType(LogSourceType.APPLICATION);
                                    sourceRepository.persist(s);
                                    return s;
                                });
    }

    @AfterEach
    void tearDown() {
        recordingSearch.reset();
        stubGeoIpEnricher.reset();
    }

    @Test
    void parsedEventsBecomeSearchableInStoreAfterParsing() throws IOException {
        String logContent =
                "203.0.113.15 - charlie [14/Sep/2026:10:15:30 +0000] \"GET /admin/dashboard"
                        + " HTTP/1.1\" 200 1024 \"https://example.test/\" \"Mozilla/5.0\"\n"
                        + "198.51.100.8 - evil [14/Sep/2026:10:15:32 +0000] \"POST /api/sql-inject"
                        + " HTTP/1.1\" 500 256 \"-\" \"sqlmap/1.7\"\n";

        Path file = tempDir.resolve("access.log");
        Files.write(file, logContent.getBytes(StandardCharsets.UTF_8));

        Long uploadId =
                QuarkusTransaction.requiringNew()
                        .call(
                                () -> {
                                    LogUpload upload = new LogUpload();
                                    upload.setSource(source);
                                    upload.setFileName("access.log");
                                    upload.setContentType("text/plain");
                                    upload.setFileSize(Files.size(file));
                                    upload.setChecksumSha256("test-sha");
                                    upload.setStoragePath(file.toString());
                                    upload.setStatus(LogUploadStatus.PROCESSING);
                                    upload.setDetectedFormat(LogFormat.ACCESS_LOG);
                                    upload.setUploadedBy("search-tester");
                                    uploadRepository.persist(upload);
                                    return upload.getId();
                                });

        LogIngestEvent ingestEvent =
                new LogIngestEvent(
                        uploadId,
                        source.getId(),
                        source.getName(),
                        "APPLICATION",
                        "access.log",
                        "text/plain",
                        Files.size(file),
                        "test-sha",
                        file.toString(),
                        "search-tester",
                        Instant.now());

        // Parse file, persist events into PostgreSQL, and index into OpenSearch store
        parser.parse(ingestEvent);

        // Verify upload reached INGESTED status
        LogUpload completed =
                QuarkusTransaction.requiringNew().call(() -> uploadRepository.findById(uploadId));
        assertEquals(LogUploadStatus.INGESTED, completed.getStatus());
        assertEquals(2L, completed.getEventCount());

        // Refresh the index so documents become visible to queries
        restClient.performRequest(
                new Request("POST", "/" + appConfig.search().alias() + "/_refresh"));

        // Query by fullText search on message
        SearchPage page = search.search(new EventQuery.Builder().fullText("dashboard").build());

        assertEquals(1, page.totalHits());
        assertEquals(1, page.hits().size());
        EventHit hit = page.hits().get(0);
        assertEquals("GET /admin/dashboard HTTP/1.1", hit.message());
        assertEquals(Severity.INFO, hit.severity());
        assertEquals("charlie", hit.fields().get("user"));
        assertEquals("203.0.113.15", hit.fields().get("srcIp"));
        assertEquals("/admin/dashboard", hit.fields().get("path"));
        assertEquals(200, hit.fields().get("status"));

        // Query by substring on raw
        SearchPage substringPage =
                search.search(
                        new EventQuery.Builder().substring("sqlmap").withFacets(true).build());

        assertEquals(1, substringPage.totalHits());
        assertFalse(substringPage.hits().isEmpty());
        EventHit evilHit = substringPage.hits().get(0);
        assertEquals("POST /api/sql-inject HTTP/1.1", evilHit.message());
        assertEquals(500, evilHit.fields().get("status"));
        assertEquals("198.51.100.8", evilHit.fields().get("srcIp"));

        // Verify facets are computed
        assertNotNull(substringPage.facets());
        assertEquals(1L, substringPage.facets().bySeverity().get("INFO"));
    }

    @Test
    void anEnrichedEventIsSearchableWithItsGeoFields() throws IOException {
        // %test runs with app.geoip.enabled=false, so the real MaxMindGeoIpEnricher never runs;
        // the stub stands in for it as the GeoIpEnricher CDI bean, same as RecordingEventSearch
        // stands in for the real EventSearch.
        String clientIp = "203.0.113.15";
        stubGeoIpEnricher.answer(
                clientIp,
                new GeoEnrichment(
                        "US", "United States", "Springfield", 39.78, -89.65, 15169L, "GOOGLE"));

        String logContent =
                clientIp
                        + " - charlie [14/Sep/2026:10:15:30 +0000] \"GET /admin/dashboard"
                        + " HTTP/1.1\" 200 1024 \"https://example.test/\" \"Mozilla/5.0\"\n";

        Path file = tempDir.resolve("access-geo.log");
        Files.write(file, logContent.getBytes(StandardCharsets.UTF_8));

        Long uploadId =
                QuarkusTransaction.requiringNew()
                        .call(
                                () -> {
                                    LogUpload upload = new LogUpload();
                                    upload.setSource(source);
                                    upload.setFileName("access-geo.log");
                                    upload.setContentType("text/plain");
                                    upload.setFileSize(Files.size(file));
                                    upload.setChecksumSha256("test-sha-geo");
                                    upload.setStoragePath(file.toString());
                                    upload.setStatus(LogUploadStatus.PROCESSING);
                                    upload.setDetectedFormat(LogFormat.ACCESS_LOG);
                                    upload.setUploadedBy("search-tester");
                                    uploadRepository.persist(upload);
                                    return upload.getId();
                                });

        LogIngestEvent ingestEvent =
                new LogIngestEvent(
                        uploadId,
                        source.getId(),
                        source.getName(),
                        "APPLICATION",
                        "access-geo.log",
                        "text/plain",
                        Files.size(file),
                        "test-sha-geo",
                        file.toString(),
                        "search-tester",
                        Instant.now());

        // Parse file, persist events into PostgreSQL (with the stub's geo enrichment applied to
        // the payload), and index into OpenSearch store.
        parser.parse(ingestEvent);

        LogUpload completed =
                QuarkusTransaction.requiringNew().call(() -> uploadRepository.findById(uploadId));
        assertEquals(LogUploadStatus.INGESTED, completed.getStatus());
        assertEquals(1L, completed.getEventCount());

        // Refresh the index so the document becomes visible to queries
        restClient.performRequest(
                new Request("POST", "/" + appConfig.search().alias() + "/_refresh"));

        SearchPage page = search.search(new EventQuery.Builder().fullText("dashboard").build());

        assertEquals(1, page.totalHits());
        EventHit hit = page.hits().get(0);
        assertEquals("203.0.113.15", hit.fields().get("srcIp"));
        // Geo has no dedicated accessor on EventHit: like every other parsed field, it surfaces
        // through the generic fields map, camelCase, matching the payload's own key names.
        // geoAsn is indexed as OpenSearch `long`, but Jackson may hand back either an Integer or
        // a Long for it, so compare numerically.
        assertEquals("US", hit.fields().get("geoCountryIso"));
        assertEquals(15169L, ((Number) hit.fields().get("geoAsn")).longValue());
    }
}
