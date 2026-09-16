package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class IndexableEventTest {

    @Test
    void readsEveryStandardFieldOutOfThePayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("format", "ACCESS_LOG");
        payload.put("host", "web-01");
        payload.put("srcIp", "203.0.113.7");
        payload.put("srcPort", 44120);
        payload.put("user", "alice");
        payload.put("method", "GET");
        payload.put("path", "/admin/login");
        payload.put("protocol", "HTTP/1.1");
        payload.put("status", 401);
        payload.put("bytes", 512);
        payload.put("referrer", "https://example.test/");
        payload.put("userAgent", "curl/8.4.0");

        IndexableEvent event = indexable(payload);

        assertEquals("ACCESS_LOG", event.format());
        assertEquals("web-01", event.host());
        assertEquals("203.0.113.7", event.srcIp());
        assertEquals(44120, event.srcPort());
        assertEquals("alice", event.user());
        assertEquals("GET", event.method());
        assertEquals("/admin/login", event.path());
        assertEquals("HTTP/1.1", event.protocol());
        assertEquals(401, event.status());
        assertEquals(512L, event.bytes());
        assertEquals("https://example.test/", event.referrer());
        assertEquals("curl/8.4.0", event.userAgent());
    }

    @Test
    void survivesAnAbsentPayload() {
        IndexableEvent event = indexable(null);

        assertNull(event.host());
        assertTrue(event.attributes().isEmpty());
        assertEquals(7L, event.eventId());
    }

    @Test
    void keepsUnplacedKeysInAttributes() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("host", "web-01");
        payload.put("attributes", Map.of("tenant", "acme", "rule", 12));

        IndexableEvent event = indexable(payload);

        assertEquals("acme", event.attributes().get("tenant"));
        assertEquals(12, event.attributes().get("rule"));
    }

    @Test
    void ignoresAFieldOfTheWrongType() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("status", "not a number");
        payload.put("srcPort", "neither");

        IndexableEvent event = indexable(payload);

        assertNull(event.status());
        assertNull(event.srcPort());
    }

    @Test
    void ignoresAnAttributesValueThatIsNotAnObject() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("attributes", "a string, not an object");

        assertTrue(indexable(payload).attributes().isEmpty());
    }

    private IndexableEvent indexable(Map<String, Object> payload) {
        return new IndexableEvent.Builder()
                .eventId(7L)
                .sourceId(3L)
                .occurredAt(Instant.parse("2026-09-01T10:00:00Z"))
                .ingestedAt(Instant.parse("2026-09-01T10:00:05Z"))
                .severity(Severity.ERROR)
                .message("failed login")
                .raw("raw line")
                .payload(payload)
                .build();
    }
}
