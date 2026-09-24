package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    @Test
    void geoFieldsAreLiftedOutOfThePayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("geoCountryIso", "US");
        payload.put("geoCountryName", "United States");
        payload.put("geoCity", "Mountain View");
        payload.put("geoAsn", 15169);
        payload.put("geoAsOrg", "Google LLC");
        payload.put("geoLocation", Map.of("lat", 37.386, "lon", -122.084));

        IndexableEvent event = indexable(payload);

        assertEquals("US", event.geoCountryIso());
        assertEquals("United States", event.geoCountryName());
        assertEquals("Mountain View", event.geoCity());
        assertEquals(15169L, event.geoAsn().longValue());
        assertEquals("Google LLC", event.geoAsOrg());
        assertEquals(37.386, event.geoLatitude(), 0.001);
        assertEquals(-122.084, event.geoLongitude(), 0.001);
    }

    @Test
    void geoFieldsDoNotLeakIntoAttributes() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("geoCountryIso", "RO");
        payload.put("attributes", Map.of("custom_key", "kept"));

        IndexableEvent event = indexable(payload);

        assertEquals("RO", event.geoCountryIso());
        assertFalse(event.attributes().containsKey("geoCountryIso"));
        assertEquals("kept", event.attributes().get("custom_key"));
    }

    @Test
    void anAbsentGeoLocationLeavesCoordinatesNull() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("geoCountryIso", "RO");

        IndexableEvent event = indexable(payload);

        assertNull(event.geoLatitude());
        assertNull(event.geoLongitude());
    }

    @Test
    void aGeoLocationOfTheWrongShapeIsIgnored() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("geoLocation", "37.386,-122.084");

        IndexableEvent event = indexable(payload);

        assertNull(event.geoLatitude());
        assertNull(event.geoLongitude());
    }

    @Test
    void userAgentFieldsAreLiftedOutOfThePayload() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("uaBrowser", "Chrome");
        payload.put("uaBrowserVersion", "120.0.0.0");
        payload.put("uaOs", "Windows NT");
        payload.put("uaOsVersion", ">=10");
        payload.put("uaDeviceClass", "Desktop");
        payload.put("uaAgentClass", "Robot");
        payload.put("uaBot", true);

        IndexableEvent event = indexable(payload);

        assertEquals("Chrome", event.uaBrowser());
        assertEquals("120.0.0.0", event.uaBrowserVersion());
        assertEquals("Windows NT", event.uaOs());
        assertEquals(">=10", event.uaOsVersion());
        assertEquals("Desktop", event.uaDeviceClass());
        assertEquals("Robot", event.uaAgentClass());
        assertEquals(Boolean.TRUE, event.uaBot());
    }

    @Test
    void anAbsentBotFlagStaysNullRatherThanFalse() {
        // Null means "not classified"; false would claim the agent was examined and found human.
        assertNull(indexable(Map.of("uaBrowser", "Chrome")).uaBot());
    }

    @Test
    void aBotFlagThatIsNotABooleanIsIgnored() {
        assertNull(indexable(Map.of("uaBot", "true")).uaBot());
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
