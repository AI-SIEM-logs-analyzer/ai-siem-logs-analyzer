package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class JsonLogParserTest {

    private static final Instant NOW = Instant.parse("2026-09-14T12:00:00Z");

    private final JsonLogParser parser =
            new JsonLogParser(
                    JsonFieldMapping.defaults(), Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);

    // --- Default mapping ---------------------------------------------------------------------

    @Test
    void ecsLineFillsEveryStandardFieldAndKeepsTheRestNested() {
        String line =
                "{\"@timestamp\":\"2026-09-14T10:15:30.123Z\",\"host\":{\"name\":\"web-01\"},"
                        + "\"source\":{\"ip\":\"203.0.113.9\",\"port\":51234},"
                        + "\"user\":{\"name\":\"alice\"},"
                        + "\"http\":{\"request\":{\"method\":\"get\",\"referrer\":\"https://a.example/\"},"
                        + "\"version\":\"1.1\",\"response\":{\"status_code\":403,"
                        + "\"body\":{\"bytes\":512}}},"
                        + "\"url\":{\"original\":\"/admin?x=1\"},"
                        + "\"user_agent\":{\"original\":\"curl/8.5.0\"},"
                        + "\"log\":{\"level\":\"warn\",\"logger\":\"access\"},"
                        + "\"message\":\"forbidden\",\"event\":{\"action\":\"deny\"}}";

        NormalizedEvent event = parse(line);

        assertEquals(Instant.parse("2026-09-14T10:15:30.123Z"), event.timestamp());
        assertEquals(LogFormat.JSON, event.format());
        assertEquals("web-01", event.host());
        assertEquals("203.0.113.9", event.srcIp());
        assertEquals(51234, event.srcPort());
        assertEquals("alice", event.user());
        assertEquals("GET", event.method());
        assertEquals("/admin?x=1", event.path());
        assertEquals("1.1", event.protocol());
        assertEquals(403, event.status());
        assertEquals(512L, event.bytes());
        assertEquals("https://a.example/", event.referrer());
        assertEquals("curl/8.5.0", event.userAgent());
        assertEquals(Severity.WARNING, event.severity());
        assertEquals("forbidden", event.message());
        assertEquals(line, event.raw());
        // Mapped values are taken out, and an object left empty by that goes with them; what no
        // field claimed keeps its place in the tree.
        assertEquals(
                Map.of("log", Map.of("logger", "access"), "event", Map.of("action", "deny")),
                event.attributes());
    }

    @Test
    void flatDottedKeysResolveLikeNestedObjects() {
        NormalizedEvent event =
                parse(
                        "{\"@timestamp\":\"2026-09-14T10:15:30Z\",\"log.level\":\"error\","
                                + "\"source.ip\":\"198.51.100.7\",\"service\":{\"name\":\"api\"}}");

        assertEquals(Severity.ERROR, event.severity());
        assertEquals("198.51.100.7", event.srcIp());
        assertEquals(Map.of("service", Map.of("name", "api")), event.attributes());
    }

    @Test
    void nginxEscapeJsonLineWithStringNumbersAndApacheTime() {
        NormalizedEvent event =
                parse(
                        "{\"time_local\":\"14/Sep/2026:13:15:30 +0300\","
                                + "\"remote_addr\":\"192.0.2.10\",\"remote_user\":\"\","
                                + "\"request_method\":\"POST\",\"request_uri\":\"/login\","
                                + "\"server_protocol\":\"HTTP/2.0\",\"status\":\"401\","
                                + "\"body_bytes_sent\":\"87\",\"http_referer\":\"\","
                                + "\"http_user_agent\":\"Mozilla/5.0\",\"request_time\":\"0.004\"}");

        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals("192.0.2.10", event.srcIp());
        // nginx writes an empty string for a missing value; the event normalises it to null.
        assertNull(event.user());
        assertNull(event.referrer());
        assertEquals("POST", event.method());
        assertEquals("/login", event.path());
        assertEquals("HTTP/2.0", event.protocol());
        assertEquals(401, event.status());
        assertEquals(87L, event.bytes());
        assertEquals("Mozilla/5.0", event.userAgent());
        assertEquals(Map.of("request_time", "0.004"), event.attributes());
    }

    @Test
    void pinoLineWithNumericLevelAndEpochMillis() {
        NormalizedEvent event =
                parse(
                        "{\"level\":50,\"time\":1789380930123,\"pid\":4242,"
                                + "\"hostname\":\"api-1\",\"msg\":\"boom\"}");

        assertEquals(Severity.ERROR, event.severity());
        assertEquals(Instant.ofEpochMilli(1789380930123L), event.timestamp());
        assertEquals("api-1", event.host());
        assertEquals("boom", event.message());
        assertEquals(Map.of("pid", 4242), event.attributes());
    }

    @Test
    void epochTimestampUnitIsTakenFromItsMagnitude() {
        assertEquals(
                Instant.ofEpochSecond(1789380930L, 250_000_000),
                parse("{\"ts\":1789380930.25}").timestamp());
        assertEquals(
                Instant.ofEpochSecond(1789380930L, 123_456_000),
                parse("{\"ts\":1789380930123456}").timestamp());
        assertEquals(
                Instant.ofEpochSecond(1789380930L, 123_456_789),
                parse("{\"ts\":1789380930123456789}").timestamp());
        assertEquals(
                Instant.ofEpochSecond(1789380930L), parse("{\"ts\":\"1789380930\"}").timestamp());
    }

    @Test
    void pythonTimestampWithoutOffsetIsReadInTheConfiguredZone() {
        JsonLogParser bucharest =
                new JsonLogParser(
                        JsonFieldMapping.defaults(),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        ZoneId.of("Europe/Bucharest"));

        NormalizedEvent event =
                bucharest
                        .parse(
                                "{\"asctime\":\"x\",\"timestamp\":\"2026-09-14 13:15:30,123\","
                                        + "\"levelname\":\"CRITICAL\",\"name\":\"worker\"}")
                        .orElseThrow();

        assertEquals(Instant.parse("2026-09-14T10:15:30.123Z"), event.timestamp());
        assertEquals(Severity.CRITICAL, event.severity());
    }

    @Test
    void offsetWithoutColonAndRfc1123TimestampsAreAccepted() {
        assertEquals(
                Instant.parse("2026-09-14T10:15:30Z"),
                parse("{\"time\":\"2026-09-14T13:15:30+0300\"}").timestamp());
        assertEquals(
                Instant.parse("2026-09-14T10:15:30Z"),
                parse("{\"date\":\"Mon, 14 Sep 2026 10:15:30 GMT\"}").timestamp());
    }

    @Test
    void severityWordsFromCommonLoggersAreMapped() {
        Map<String, Severity> expected =
                Map.ofEntries(
                        Map.entry("TRACE", Severity.DEBUG),
                        Map.entry("debug", Severity.DEBUG),
                        Map.entry("Info", Severity.INFO),
                        Map.entry("notice", Severity.INFO),
                        Map.entry("WARN", Severity.WARNING),
                        Map.entry("warning", Severity.WARNING),
                        Map.entry("err", Severity.ERROR),
                        Map.entry("SEVERE", Severity.ERROR),
                        Map.entry("fatal", Severity.CRITICAL),
                        Map.entry("panic", Severity.CRITICAL),
                        Map.entry("emerg", Severity.CRITICAL));

        expected.forEach(
                (level, severity) ->
                        assertEquals(
                                severity,
                                parse("{\"level\":\"" + level + "\"}").severity(),
                                level));
    }

    @Test
    void syslogNumericSeverityIsMapped() {
        assertEquals(Severity.CRITICAL, parse("{\"severity\":2}").severity());
        assertEquals(Severity.WARNING, parse("{\"severity\":\"4\"}").severity());
        assertEquals(Severity.DEBUG, parse("{\"severity\":7}").severity());
    }

    @Test
    void unknownSeverityKeepsTheDefaultAndStaysInAttributes() {
        NormalizedEvent event = parse("{\"level\":\"chatty\"}");

        assertEquals(Severity.INFO, event.severity());
        assertEquals(Map.of("level", "chatty"), event.attributes());
    }

    // --- Candidates and coercion -------------------------------------------------------------

    @Test
    void firstCandidateWithAUsableValueWins() {
        NormalizedEvent event =
                parse("{\"http\":{\"response\":{\"status_code\":\"n/a\"}},\"status\":503}");

        assertEquals(503, event.status());
        // The unusable candidate was not consumed.
        assertEquals(
                Map.of("http", Map.of("response", Map.of("status_code", "n/a"))),
                event.attributes());
    }

    @Test
    void valuesOfTheWrongTypeOrOutOfRangeStayInAttributes() {
        NormalizedEvent event =
                parse(
                        "{\"src_port\":70000,\"bytes\":-1,\"method\":{\"verb\":\"GET\"},"
                                + "\"status\":\"success\",\"host\":{\"ip\":[\"10.0.0.1\"]}}");

        assertNull(event.srcPort());
        assertNull(event.bytes());
        assertNull(event.method());
        assertNull(event.status());
        assertNull(event.host());
        assertEquals(
                Map.of(
                        "src_port",
                        70000,
                        "bytes",
                        -1,
                        "method",
                        Map.of("verb", "GET"),
                        "status",
                        "success",
                        "host",
                        Map.of("ip", List.of("10.0.0.1"))),
                event.attributes());
    }

    @Test
    void missingTimestampFallsBackToTheClock() {
        NormalizedEvent event = parse("{\"message\":\"no clock on the sender\"}");

        assertEquals(NOW, event.timestamp());
        assertTrue(event.attributes().isEmpty());
    }

    @Test
    void unparseableTimestampFallsBackToTheClockAndIsKept() {
        NormalizedEvent event = parse("{\"timestamp\":\"yesterday-ish\"}");

        assertEquals(NOW, event.timestamp());
        assertEquals(Map.of("timestamp", "yesterday-ish"), event.attributes());
    }

    @Test
    void nullsEmptyObjectsAndNumberTypesSurviveInAttributes() {
        NormalizedEvent event =
                parse(
                        "{\"user\":null,\"ctx\":{},\"ratio\":0.5,\"big\":9007199254740993,"
                                + "\"flags\":[true,null,\"x\"]}");

        assertNull(event.user());
        Map<String, Object> attributes = event.attributes();
        assertTrue(attributes.containsKey("user"));
        assertNull(attributes.get("user"));
        assertEquals(Map.of(), attributes.get("ctx"));
        assertEquals(new BigDecimal("0.5"), attributes.get("ratio"));
        assertEquals(9007199254740993L, attributes.get("big"));
        assertEquals(Arrays.asList(true, null, "x"), attributes.get("flags"));
        assertEquals(
                List.of("user", "ctx", "ratio", "big", "flags"), List.copyOf(attributes.keySet()));
    }

    @Test
    void nestedAttributesAreReadOnly() {
        NormalizedEvent event = parse("{\"ctx\":{\"tags\":[\"a\"]}}");

        @SuppressWarnings("unchecked")
        Map<String, Object> ctx = (Map<String, Object>) event.attributes().get("ctx");
        assertThrows(UnsupportedOperationException.class, () -> ctx.put("k", "v"));
        assertThrows(
                UnsupportedOperationException.class, () -> ((List<?>) ctx.get("tags")).clear());
    }

    // --- Custom mapping ----------------------------------------------------------------------

    @Test
    void customMappingReplacesTheDefaultsForAField() {
        JsonFieldMapping cloudTrail =
                JsonFieldMapping.defaults()
                        .withField(JsonFieldMapping.Field.TIMESTAMP, List.of("eventTime"))
                        .withField(JsonFieldMapping.Field.SRC_IP, List.of("sourceIPAddress"))
                        .withField(
                                JsonFieldMapping.Field.USER,
                                List.of("userIdentity.userName", "userIdentity.arn"))
                        .withField(JsonFieldMapping.Field.MESSAGE, List.of("eventName"));
        JsonLogParser custom =
                new JsonLogParser(cloudTrail, Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);

        NormalizedEvent event =
                custom.parse(
                                "{\"eventTime\":\"2026-09-14T10:15:30Z\","
                                        + "\"sourceIPAddress\":\"203.0.113.50\","
                                        + "\"userIdentity\":{\"type\":\"IAMUser\","
                                        + "\"arn\":\"arn:aws:iam::1:user/bob\"},"
                                        + "\"eventName\":\"ConsoleLogin\","
                                        + "\"timestamp\":\"1999-01-01T00:00:00Z\"}")
                        .orElseThrow();

        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals("203.0.113.50", event.srcIp());
        assertEquals("arn:aws:iam::1:user/bob", event.user());
        assertEquals("ConsoleLogin", event.message());
        // "timestamp" is no longer a candidate, so it is just another attribute.
        assertEquals(
                Map.of(
                        "userIdentity",
                        Map.of("type", "IAMUser"),
                        "timestamp",
                        "1999-01-01T00:00:00Z"),
                event.attributes());
    }

    @Test
    void emptyCandidateListLeavesTheFieldUnmapped() {
        JsonLogParser noMessage =
                new JsonLogParser(
                        JsonFieldMapping.defaults()
                                .withField(JsonFieldMapping.Field.MESSAGE, List.of()),
                        Clock.fixed(NOW, ZoneOffset.UTC),
                        ZoneOffset.UTC);

        NormalizedEvent event = noMessage.parse("{\"message\":\"hi\"}").orElseThrow();

        assertNull(event.message());
        assertEquals(Map.of("message", "hi"), event.attributes());
    }

    @Test
    void malformedPathsAreRejected() {
        for (String path : List.of("", " ", ".a", "a.", "a..b")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () ->
                            JsonFieldMapping.defaults()
                                    .withField(JsonFieldMapping.Field.HOST, List.of(path)),
                    path);
        }
    }

    // --- Rejections --------------------------------------------------------------------------

    @Test
    void linesThatAreNotOneJsonObjectAreRejected() {
        for (String line :
                List.of(
                        "",
                        "   ",
                        "not json",
                        "{\"a\":",
                        "[{\"a\":1}]",
                        "\"text\"",
                        "42",
                        "null",
                        "{\"a\":1} trailing",
                        "{\"a\":1}{\"b\":2}")) {
            assertFalse(parser.parse(line).isPresent(), line);
        }
    }

    @Test
    void duplicateKeysAreRejected() {
        // Two values for one key is how a line shows one user to one reader and another user to
        // the next, so the line is refused rather than resolved either way.
        assertFalse(parser.parse("{\"user\":\"admin\",\"user\":\"guest\"}").isPresent());
    }

    @Test
    void excessiveNestingIsRejected() {
        String deep = "{\"a\":".repeat(1_000) + "1" + "}".repeat(1_000);

        assertFalse(parser.parse(deep).isPresent());
    }

    @Test
    void hugeNumericExponentIsNotExpandedIntoATimestamp() {
        // BigDecimal keeps 1e20000000 compact, but rescaling it to whole seconds builds a
        // twenty-million-digit number: seconds of CPU per value from a ten-byte literal. Larger
        // exponents are cheap again only because BigInteger gives up on them outright.
        NormalizedEvent event =
                assertTimeoutPreemptively(
                        Duration.ofSeconds(1),
                        () -> parse("{\"ts\":1e20000000,\"time\":1e-20000000}"));

        assertEquals(NOW, event.timestamp());
        assertEquals(2, event.attributes().size());
    }

    private NormalizedEvent parse(String line) {
        Optional<NormalizedEvent> event = parser.parse(line);
        assertTrue(event.isPresent(), () -> "expected a match: " + line);
        return event.get();
    }
}
