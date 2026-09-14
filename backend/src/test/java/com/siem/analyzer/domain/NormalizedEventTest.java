package com.siem.analyzer.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NormalizedEventTest {

    private static final Instant TS = Instant.parse("2026-09-14T10:15:30Z");
    private static final String RAW =
            "10.0.0.7 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login HTTP/1.1\" 401 512 \"-\""
                    + " \"curl/8.4.0\"";

    @Test
    void builderCarriesEveryStandardField() {
        NormalizedEvent event =
                NormalizedEvent.builder(TS, LogFormat.PLAIN, RAW)
                        .host("web-01")
                        .srcIp("10.0.0.7")
                        .srcPort(51514)
                        .user("alice")
                        .method("GET")
                        .path("/login")
                        .protocol("HTTP/1.1")
                        .status(401)
                        .bytes(512L)
                        .referrer("https://example.test/")
                        .userAgent("curl/8.4.0")
                        .severity(Severity.WARNING)
                        .message("GET /login 401")
                        .attributes(Map.of("vhost", "example.test"))
                        .build();

        assertEquals(TS, event.timestamp());
        assertEquals(LogFormat.PLAIN, event.format());
        assertEquals("web-01", event.host());
        assertEquals("10.0.0.7", event.srcIp());
        assertEquals(51514, event.srcPort());
        assertEquals("alice", event.user());
        assertEquals("GET", event.method());
        assertEquals("/login", event.path());
        assertEquals("HTTP/1.1", event.protocol());
        assertEquals(401, event.status());
        assertEquals(512L, event.bytes());
        assertEquals("https://example.test/", event.referrer());
        assertEquals("curl/8.4.0", event.userAgent());
        assertEquals(Severity.WARNING, event.severity());
        assertEquals("GET /login 401", event.message());
        assertEquals(RAW, event.raw());
        assertEquals(Map.of("vhost", "example.test"), event.attributes());
    }

    @Test
    void onlyTimestampFormatAndRawAreRequired() {
        NormalizedEvent event = NormalizedEvent.builder(TS, LogFormat.SYSLOG, "hello").build();

        assertNull(event.srcIp());
        assertNull(event.method());
        assertNull(event.status());
        assertNull(event.userAgent());
        assertEquals(Severity.INFO, event.severity());
        assertTrue(event.attributes().isEmpty());
    }

    @Test
    void rejectsMissingRequiredFields() {
        assertThrows(
                NullPointerException.class,
                () -> NormalizedEvent.builder(null, LogFormat.JSON, RAW).build());
        assertThrows(
                NullPointerException.class, () -> NormalizedEvent.builder(TS, null, RAW).build());
        assertThrows(
                NullPointerException.class,
                () -> NormalizedEvent.builder(TS, LogFormat.JSON, null).build());
    }

    @Test
    void keepsRawExactlyAsReceived() {
        String padded = "  line with trailing space \t";

        NormalizedEvent event = NormalizedEvent.builder(TS, LogFormat.PLAIN, padded).build();

        assertEquals(padded, event.raw());
    }

    @Test
    void blankOptionalTextBecomesAbsent() {
        NormalizedEvent event =
                NormalizedEvent.builder(TS, LogFormat.CSV, RAW)
                        .srcIp("  ")
                        .user("-")
                        .userAgent("")
                        .referrer("-")
                        .path(" /login ")
                        .build();

        assertNull(event.srcIp());
        assertNull(event.user());
        assertNull(event.userAgent());
        assertNull(event.referrer());
        assertEquals("/login", event.path());
    }

    @Test
    void uppercasesTheHttpMethod() {
        NormalizedEvent event =
                NormalizedEvent.builder(TS, LogFormat.JSON, RAW).method("post").build();

        assertEquals("POST", event.method());
    }

    @Test
    void rejectsOutOfRangeNumbers() {
        assertThrows(
                IllegalArgumentException.class,
                () -> NormalizedEvent.builder(TS, LogFormat.JSON, RAW).status(42).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> NormalizedEvent.builder(TS, LogFormat.JSON, RAW).status(600).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> NormalizedEvent.builder(TS, LogFormat.JSON, RAW).srcPort(70000).build());
        assertThrows(
                IllegalArgumentException.class,
                () -> NormalizedEvent.builder(TS, LogFormat.JSON, RAW).bytes(-1L).build());
    }

    @Test
    void attributesAreCopiedAndReadOnly() {
        Map<String, Object> source = new HashMap<>();
        source.put("k", "v");
        source.put("nullable", null);

        NormalizedEvent event =
                NormalizedEvent.builder(TS, LogFormat.JSON, RAW).attributes(source).build();
        source.put("later", "ignored");

        assertEquals(2, event.attributes().size());
        assertTrue(event.attributes().containsKey("nullable"));
        assertThrows(UnsupportedOperationException.class, () -> event.attributes().put("x", "y"));
    }

    @Test
    void attributesKeepInsertionOrder() {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("z", 1);
        source.put("a", 2);

        NormalizedEvent event =
                NormalizedEvent.builder(TS, LogFormat.JSON, RAW).attributes(source).build();

        assertEquals("[z, a]", event.attributes().keySet().toString());
    }
}
