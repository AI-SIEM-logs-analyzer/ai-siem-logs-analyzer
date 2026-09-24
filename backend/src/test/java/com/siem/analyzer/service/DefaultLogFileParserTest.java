package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogIngestEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.enrich.GeoEnrichment;
import com.siem.analyzer.enrich.StubGeoIpEnricher;
import com.siem.analyzer.repo.LogEventIndexStateRepository;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.search.IndexableEvent;
import com.siem.analyzer.search.RecordingEventSearch;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@QuarkusTest
class DefaultLogFileParserTest {

    @Inject DefaultLogFileParser parser;
    @Inject LogUploadRepository uploadRepository;
    @Inject LogSourceRepository sourceRepository;
    @Inject LogEventRepository eventRepository;
    @Inject LogEventIndexStateRepository indexStateRepository;
    @Inject RecordingEventSearch search;
    @Inject StubGeoIpEnricher geo;

    @TempDir Path tempDir;

    private LogSource source;

    @BeforeEach
    void setUp() {
        search.reset();
        geo.reset();
        source =
                QuarkusTransaction.requiringNew()
                        .call(
                                () -> {
                                    String name = "test-source-" + UUID.randomUUID();
                                    LogSource s = new LogSource();
                                    s.setName(name);
                                    s.setType(LogSourceType.APPLICATION);
                                    sourceRepository.persist(s);
                                    return s;
                                });
    }

    @Test
    void parsesAccessLogFileAndIndexesEvents() throws IOException {
        String content =
                "203.0.113.9 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login HTTP/1.1\" 200 512"
                        + " \"https://example.test/\" \"Mozilla/5.0\"\n"
                        + "198.51.100.2 - - [14/Sep/2026:10:15:35 +0000] \"POST /api/data"
                        + " HTTP/1.1\" 401 128 \"-\" \"curl/8.4.0\"\n";

        Path file = write("access.log", content);
        Long uploadId = createUpload(file, LogFormat.ACCESS_LOG);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        LogUpload upload = readUpload(uploadId);
        assertEquals(LogUploadStatus.INGESTED, upload.getStatus());
        assertEquals(2L, upload.getEventCount());
        assertNotNull(upload.getProcessedAt());

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(2, events.size());

        LogEvent first = events.get(0);
        assertEquals("GET /login HTTP/1.1", first.getMessage());
        assertEquals(Severity.INFO, first.getSeverity());
        assertNotNull(first.getPayload());
        assertEquals("ACCESS_LOG", first.getPayload().get("format"));
        assertEquals("203.0.113.9", first.getPayload().get("srcIp"));
        assertEquals("alice", first.getPayload().get("user"));
        assertEquals("GET", first.getPayload().get("method"));
        assertEquals("/login", first.getPayload().get("path"));
        assertEquals(200, first.getPayload().get("status"));
        assertEquals(512, ((Number) first.getPayload().get("bytes")).intValue());

        List<IndexableEvent> indexed = search.indexed();
        assertEquals(2, indexed.size());
        assertEquals(
                events.stream().map(LogEvent::getId).sorted().toList(),
                indexed.stream().map(IndexableEvent::eventId).sorted().toList());
        assertTrue(indexStateRepository.listUnindexed(10).isEmpty());
    }

    @Test
    void geoFieldsLandInThePayload() throws IOException {
        geo.answer(
                "8.8.8.8",
                new GeoEnrichment(
                        "US",
                        "United States",
                        "Mountain View",
                        37.386,
                        -122.084,
                        15169L,
                        "Google LLC"));

        String content =
                "8.8.8.8 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login HTTP/1.1\" 200 512"
                        + " \"https://example.test/\" \"Mozilla/5.0\"\n";

        Path file = write("access-geo.log", content);
        Long uploadId = createUpload(file, LogFormat.ACCESS_LOG);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(1, events.size());
        Map<String, Object> payload = events.get(0).getPayload();

        assertEquals("US", payload.get("geoCountryIso"));
        assertEquals("United States", payload.get("geoCountryName"));
        assertEquals("Mountain View", payload.get("geoCity"));
        assertEquals(15169L, ((Number) payload.get("geoAsn")).longValue());
        assertEquals("Google LLC", payload.get("geoAsOrg"));

        Map<?, ?> location = (Map<?, ?>) payload.get("geoLocation");
        assertEquals(37.386, ((Number) location.get("lat")).doubleValue(), 0.001);
        assertEquals(-122.084, ((Number) location.get("lon")).doubleValue(), 0.001);
    }

    @Test
    void anEventWithoutASourceAddressGetsNoGeoKeys() throws IOException {
        String content =
                "<34>1 2026-09-14T22:14:15.003Z host1 sshd 1234 ID47 - Failed password for root\n";

        Path file = write("syslog-no-geo.log", content);
        Long uploadId = createUpload(file, LogFormat.SYSLOG);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(1, events.size());
        Map<String, Object> payload = events.get(0).getPayload();

        assertFalse(payload.containsKey("geoCountryIso"));
        assertFalse(payload.containsKey("geoLocation"));
    }

    @Test
    void anAddressWithNoGeoDataGetsNoGeoKeys() throws IOException {
        String content =
                "203.0.113.7 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login HTTP/1.1\" 200 512"
                        + " \"https://example.test/\" \"Mozilla/5.0\"\n";

        Path file = write("access-no-geo.log", content);
        Long uploadId = createUpload(file, LogFormat.ACCESS_LOG);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(1, events.size());
        Map<String, Object> payload = events.get(0).getPayload();

        assertFalse(payload.containsKey("geoCountryIso"));
        assertFalse(payload.containsKey("geoAsn"));
    }

    @Test
    void parsesSyslogFileAndIndexesEvents() throws IOException {
        String content =
                "<34>1 2026-09-14T22:14:15.003Z host1 sshd 1234 ID47 - Failed password for root\n"
                        + "Sep 14 10:15:30 web-01 kernel: Out of memory: Kill process 9999\n";

        Path file = write("syslog.log", content);
        Long uploadId = createUpload(file, LogFormat.SYSLOG);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        LogUpload upload = readUpload(uploadId);
        assertEquals(LogUploadStatus.INGESTED, upload.getStatus());
        assertEquals(2L, upload.getEventCount());

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(2, events.size());
        assertEquals(2, search.indexed().size());
        assertTrue(indexStateRepository.listUnindexed(10).isEmpty());
    }

    @Test
    void parsesJsonLogFileAndIndexesEvents() throws IOException {
        String content =
                "{\"timestamp\":\"2026-09-14T10:15:30Z\",\"message\":\"auth success\","
                        + "\"user\":{\"name\":\"bob\"},\"source\":{\"ip\":\"10.0.0.1\"},"
                        + "\"log\":{\"level\":\"info\"}}\n"
                        + "{\"timestamp\":\"2026-09-14T10:15:32Z\",\"message\":\"auth failed\","
                        + "\"source\":{\"ip\":\"10.0.0.2\"},\"log\":{\"level\":\"warn\"}}\n";

        Path file = write("events.json", content);
        Long uploadId = createUpload(file, LogFormat.JSON);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        LogUpload upload = readUpload(uploadId);
        assertEquals(LogUploadStatus.INGESTED, upload.getStatus());
        assertEquals(2L, upload.getEventCount());

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(2, events.size());

        LogEvent first = events.get(0);
        assertEquals("auth success", first.getMessage());
        assertEquals("bob", first.getPayload().get("user"));
        assertEquals("10.0.0.1", first.getPayload().get("srcIp"));
        assertEquals(Severity.INFO, first.getSeverity());

        assertEquals(2, search.indexed().size());
    }

    @Test
    void handlesPlainTextFile() throws IOException {
        String content = "An unparseable free-form line of log\nAnother unstructured line\n";

        Path file = write("plain.log", content);
        Long uploadId = createUpload(file, LogFormat.PLAIN);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        LogUpload upload = readUpload(uploadId);
        assertEquals(LogUploadStatus.INGESTED, upload.getStatus());
        assertEquals(2L, upload.getEventCount());

        List<LogEvent> events = listEvents(source.getId());
        assertEquals(2, events.size());
        assertEquals("An unparseable free-form line of log", events.get(0).getMessage());
        assertEquals(2, search.indexed().size());
    }

    @Test
    void handlesEmptyFile() throws IOException {
        Path file = write("empty.log", "\n   \n\n");
        Long uploadId = createUpload(file, LogFormat.PLAIN);
        LogIngestEvent ingestEvent = createIngestEvent(uploadId, file);

        parser.parse(ingestEvent);

        LogUpload upload = readUpload(uploadId);
        assertEquals(LogUploadStatus.INGESTED, upload.getStatus());
        assertEquals(0L, upload.getEventCount());
        assertTrue(search.indexed().isEmpty());
    }

    @Test
    void throwsWhenFileNotFound() {
        Long uploadId = createUpload(tempDir.resolve("missing.log"), LogFormat.PLAIN);
        LogIngestEvent ingestEvent =
                new LogIngestEvent(
                        uploadId,
                        source.getId(),
                        source.getName(),
                        "APPLICATION",
                        "missing.log",
                        "text/plain",
                        10L,
                        "checksum",
                        tempDir.resolve("missing.log").toString(),
                        "tester",
                        Instant.now());

        assertThrows(IllegalStateException.class, () -> parser.parse(ingestEvent));
    }

    @Test
    void throwsWhenUploadNotFound() throws IOException {
        Path file = write("test.log", "some line\n");
        LogIngestEvent ingestEvent =
                new LogIngestEvent(
                        999_999L,
                        source.getId(),
                        source.getName(),
                        "APPLICATION",
                        "test.log",
                        "text/plain",
                        10L,
                        "checksum",
                        file.toString(),
                        "tester",
                        Instant.now());

        assertThrows(NotFoundException.class, () -> parser.parse(ingestEvent));
    }

    private Path write(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    private Long createUpload(Path file, LogFormat format) {
        return QuarkusTransaction.requiringNew()
                .call(
                        () -> {
                            LogUpload upload = new LogUpload();
                            upload.setSource(source);
                            upload.setFileName(file.getFileName().toString());
                            upload.setContentType("text/plain");
                            upload.setFileSize(Files.exists(file) ? Files.size(file) : 0L);
                            upload.setChecksumSha256("sha256-test");
                            upload.setStoragePath(file.toString());
                            upload.setStatus(LogUploadStatus.PROCESSING);
                            upload.setDetectedFormat(format);
                            upload.setUploadedBy("tester");
                            uploadRepository.persist(upload);
                            return upload.getId();
                        });
    }

    private LogIngestEvent createIngestEvent(Long uploadId, Path file) throws IOException {
        return new LogIngestEvent(
                uploadId,
                source.getId(),
                source.getName(),
                source.getType().name(),
                file.getFileName().toString(),
                "text/plain",
                Files.size(file),
                "checksum",
                file.toString(),
                "tester",
                Instant.now());
    }

    private LogUpload readUpload(Long uploadId) {
        return QuarkusTransaction.requiringNew().call(() -> uploadRepository.findById(uploadId));
    }

    private List<LogEvent> listEvents(Long sourceId) {
        return QuarkusTransaction.requiringNew()
                .call(() -> eventRepository.list("source.id", sourceId));
    }
}
