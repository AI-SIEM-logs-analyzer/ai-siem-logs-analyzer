package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AccessLogParserTest {

    private final AccessLogParser parser = new AccessLogParser();

    @Test
    void combinedLineFillsEveryField() {
        String line =
                "203.0.113.9 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login?next=%2F HTTP/1.1\""
                        + " 401 512 \"https://example.test/\" \"Mozilla/5.0 (X11; Linux x86_64)\"";

        NormalizedEvent event = parse(line);

        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals(LogFormat.ACCESS_LOG, event.format());
        assertEquals("203.0.113.9", event.srcIp());
        assertEquals("alice", event.user());
        assertEquals("GET", event.method());
        assertEquals("/login?next=%2F", event.path());
        assertEquals("HTTP/1.1", event.protocol());
        assertEquals(401, event.status());
        assertEquals(512L, event.bytes());
        assertEquals("https://example.test/", event.referrer());
        assertEquals("Mozilla/5.0 (X11; Linux x86_64)", event.userAgent());
        assertEquals("GET /login?next=%2F HTTP/1.1", event.message());
        assertEquals(Severity.INFO, event.severity());
        assertEquals(line, event.raw());
        assertEquals(Map.of(), event.attributes());
    }

    @Test
    void commonLineLeavesReferrerAndUserAgentEmpty() {
        String line =
                "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200"
                        + " 2326";

        NormalizedEvent event = parse(line);

        assertEquals(Instant.parse("2000-10-10T20:55:36Z"), event.timestamp());
        assertEquals("frank", event.user());
        assertEquals("/apache_pb.gif", event.path());
        assertEquals(200, event.status());
        assertEquals(2326L, event.bytes());
        assertNull(event.referrer());
        assertNull(event.userAgent());
    }

    @Test
    void dashPlaceholdersBecomeNull() {
        NormalizedEvent event =
                parse(
                        "10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"HEAD / HTTP/1.1\" 304 - \"-\""
                                + " \"-\"");

        assertNull(event.user());
        assertNull(event.bytes());
        assertNull(event.referrer());
        assertNull(event.userAgent());
    }

    @Test
    void nginxCombinedLineWithIpv6ClientAndEscapedQuote() {
        NormalizedEvent event =
                parse(
                        "2001:db8::1 - - [14/Sep/2026:13:15:30 +0300] \"POST /api/login HTTP/2.0\""
                                + " 200 0 \"-\" \"sqlmap/1.7 \\\"probe\\\"\"");

        assertEquals("2001:db8::1", event.srcIp());
        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals("POST", event.method());
        assertEquals("HTTP/2.0", event.protocol());
        assertEquals(0L, event.bytes());
        // Escapes are kept as the server wrote them, like every other field.
        assertEquals("sqlmap/1.7 \\\"probe\\\"", event.userAgent());
    }

    @Test
    void identAndUserWithAtSignAreKept() {
        NormalizedEvent event =
                parse(
                        "10.0.0.7 ident-7 alice@example.test [14/Sep/2026:10:15:30 +0000] \"GET /"
                                + " HTTP/1.1\" 200 10");

        assertEquals("alice@example.test", event.user());
        assertEquals(Map.of("ident", "ident-7"), event.attributes());
    }

    @Test
    void requestThatIsNotMethodPathProtocolGoesOnlyToMessage() {
        // A TLS handshake sent to a plain-HTTP port: Apache logs the bytes it could not parse.
        NormalizedEvent event =
                parse(
                        "198.51.100.4 - - [14/Sep/2026:10:15:30 +0000] \"\\x16\\x03\\x01\\x02\" 400"
                                + " 226 \"-\" \"-\"");

        assertNull(event.method());
        assertNull(event.path());
        assertNull(event.protocol());
        assertEquals(400, event.status());
        assertEquals("\\x16\\x03\\x01\\x02", event.message());
    }

    @Test
    void emptyRequestFromTimedOutConnection() {
        NormalizedEvent event =
                parse("198.51.100.4 - - [14/Sep/2026:10:15:30 +0000] \"-\" 408 - \"-\" \"-\"");

        assertNull(event.method());
        assertNull(event.message());
        assertEquals(408, event.status());
    }

    @Test
    void veryLongUserAgentDoesNotExhaustTheStack() {
        // The client controls this field. A regex that recurses once per character would throw
        // StackOverflowError here and take the consumer thread with it.
        String agent = "A".repeat(200_000) + "\\\"" + "B".repeat(200_000);

        NormalizedEvent event =
                parse(
                        "10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1 \"-\" \""
                                + agent
                                + "\"");

        assertEquals(agent, event.userAgent());
    }

    @Test
    void requestWithoutProtocolToken() {
        NormalizedEvent event =
                parse("10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET /index.html\" 200 42");

        assertEquals("GET", event.method());
        assertEquals("/index.html", event.path());
        assertNull(event.protocol());
    }

    @Test
    void lineInAnotherFormatIsNotParsed() {
        assertTrue(
                parser.parse("Sep 14 10:15:30 web-01 sshd[42]: Failed password for root")
                        .isEmpty());
        assertTrue(parser.parse("").isEmpty());
    }

    @Test
    void lineWithExtraTrailingFieldsIsNotParsed() {
        assertTrue(
                parser.parse(
                                "10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1"
                                        + " \"-\" \"curl/8.4.0\" \"203.0.113.1\"")
                        .isEmpty());
    }

    @Test
    void impossibleDateIsNotParsed() {
        assertTrue(
                parser.parse("10.0.0.7 - - [31/Feb/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1")
                        .isEmpty());
    }

    @Test
    void statusOutsideHttpRangeIsNotParsed() {
        assertTrue(
                parser.parse("10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 999 1")
                        .isEmpty());
    }

    @Test
    void byteCountTooLargeForLongIsNotParsed() {
        assertTrue(
                parser.parse(
                                "10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200"
                                        + " 99999999999999999999")
                        .isEmpty());
    }

    private NormalizedEvent parse(String line) {
        Optional<NormalizedEvent> event = parser.parse(line);
        assertTrue(event.isPresent(), () -> "expected the line to parse: " + line);
        return event.get();
    }
}
