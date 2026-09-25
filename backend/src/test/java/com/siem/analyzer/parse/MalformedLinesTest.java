package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.NormalizedEvent;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What every parser promises for a line it cannot read: an empty result, never an exception, and
 * never a wait. An upload is read line by line, so one line that throws or hangs stops the whole
 * file, and the sender of a log line is not always friendly.
 *
 * <p>Whatever a parser does return keeps the line it was given as {@code raw}, byte for byte.
 */
class MalformedLinesTest {

    private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

    /** Generous for a CI runner; a regex that backtracks or recurses badly takes far longer. */
    private static final Duration PER_LINE = Duration.ofSeconds(5);

    private static final String ACCESS =
            "203.0.113.9 - alice [14/Sep/2026:10:15:30 +0000] \"GET /login?next=%2F HTTP/1.1\" 401"
                    + " 512 \"https://example.test/\" \"Mozilla/5.0 (X11; Linux x86_64)\"";

    private static final String RFC5424 =
            "<165>1 2026-09-14T22:14:15.003Z mymachine.example.com evntslog 42 ID47"
                    + " [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An application"
                    + " event";

    private static final String BSD =
            "Dec 10 07:13:43 LabSZ sshd[24227]: Failed password for root from 5.36.59.76 port"
                    + " 42393 ssh2";

    private static final String JSON =
            "{\"@timestamp\":\"2026-09-14T10:15:30Z\",\"source\":{\"ip\":\"10.0.0.1\"},"
                    + "\"user\":{\"name\":\"bob\"},\"message\":\"auth failed\"}";

    private static final SyslogParser SYSLOG =
            new SyslogParser(Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);
    private static final AccessLogParser ACCESS_PARSER = new AccessLogParser();
    private static final JsonLogParser JSON_PARSER =
            new JsonLogParser(
                    JsonFieldMapping.defaults(), Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);

    private static final Map<String, Function<String, Optional<NormalizedEvent>>> PARSERS =
            Map.of(
                    "syslog", SYSLOG::parse,
                    "access", ACCESS_PARSER::parse,
                    "json", JSON_PARSER::parse);

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                " ",
                "\t",
                "\r",
                "\u0000",
                "\u0000\u0001\u0002\u0003",
                "﻿",
                "\uD800",
                "\uDC00\uD800",
                "-",
                "\"",
                "\\",
                "[",
                "]",
                "<",
                "<>",
                "<13>",
                "<13>1",
                "<13>1 ",
                "<999>1 - - - - - -",
                "null",
                "42",
                "\"text\"",
                "[1,2,3]",
                "{",
                "{\"a\":",
                "{\"a\":1}{\"b\":2}",
                "Dec",
                "Dec 10",
                "Dec 10 07:13",
                "Dec 32 07:13:43 host tag: day 32",
                "Feb 30 07:13:43 host tag: 30 February",
                "Dec 10 25:13:43 host tag: hour 25",
                "203.0.113.9",
                "203.0.113.9 - - [",
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1",
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200",
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" abc 1",
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 -1",
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"\\\" 200 1",
                "203.0.113.9 - - [99/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1"
            })
    void noiseIsRejectedByEveryParser(String line) {
        for (Map.Entry<String, Function<String, Optional<NormalizedEvent>>> parser :
                PARSERS.entrySet()) {
            Optional<NormalizedEvent> event = parseSafely(parser.getValue(), line);
            assertTrue(event.isEmpty(), () -> parser.getKey() + " accepted: " + escape(line));
        }
    }

    /**
     * A file cut off by a full disk, a rotation or a size-limited upload ends in half a line. Every
     * prefix of a real line of each format must be handled, whatever the cut makes of it.
     */
    @ParameterizedTest
    @ValueSource(strings = {ACCESS, RFC5424, BSD, JSON})
    void everyTruncationOfALineIsHandled(String line) {
        for (int length = 0; length <= line.length(); length++) {
            assertHandled(line.substring(0, length));
        }
    }

    @Test
    void truncatedJsonIsNeverAnEvent() {
        for (int length = 0; length < JSON.length(); length++) {
            String prefix = JSON.substring(0, length);
            assertTrue(JSON_PARSER.parse(prefix).isEmpty(), prefix);
        }
    }

    @Test
    void rfc5424CutInsideStructuredDataIsNotAnEvent() {
        int open = RFC5424.indexOf('[');
        int close = RFC5424.indexOf(']');
        for (int length = open + 1; length <= close; length++) {
            String prefix = RFC5424.substring(0, length);
            assertTrue(SYSLOG.parse(prefix).isEmpty(), prefix);
        }
    }

    @Test
    void accessLineCutInsideAQuotedFieldIsNotAnEvent() {
        int userAgent = ACCESS.lastIndexOf(" \"Mozilla");
        for (int length = userAgent + 1; length < ACCESS.length(); length++) {
            String prefix = ACCESS.substring(0, length);
            assertTrue(ACCESS_PARSER.parse(prefix).isEmpty(), prefix);
        }
    }

    /**
     * Seeded random damage to real lines: characters replaced by the ones parsers treat specially
     * or never expect, deleted, or duplicated. The seed is fixed so a failure reproduces.
     */
    @Test
    void randomlyCorruptedLinesAreHandled() throws IOException {
        List<String> seeds = new ArrayList<>(List.of(ACCESS, RFC5424, BSD, JSON));
        seeds.addAll(LoghubSamplesParseTest.sample("OpenSSH.log").subList(0, 20));
        seeds.addAll(LoghubSamplesParseTest.sample("Mac.log").subList(30, 40));
        seeds.addAll(LoghubSamplesParseTest.sample("Apache.log").subList(0, 5));
        String special = "\"\\[]{}<>:=- \t\r\n\u0000\u007Fé﻿😀\uD800%/.,0123456789";

        Random random = new Random(20260925L);
        for (int round = 0; round < 5_000; round++) {
            StringBuilder line = new StringBuilder(seeds.get(random.nextInt(seeds.size())));
            int edits = 1 + random.nextInt(4);
            for (int edit = 0; edit < edits && !line.isEmpty(); edit++) {
                int at = random.nextInt(line.length());
                switch (random.nextInt(3)) {
                    case 0 -> line.setCharAt(at, special.charAt(random.nextInt(special.length())));
                    case 1 -> line.deleteCharAt(at);
                    default -> {
                        int end = Math.min(line.length(), at + 1 + random.nextInt(8));
                        line.insert(at, line.substring(at, end));
                    }
                }
            }
            assertHandled(line.toString());
        }
    }

    /**
     * Lines built to hurt a regex engine or a scanner: each would overflow the stack, backtrack for
     * minutes or grow a structure quadratically in a naive parser.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("hostileLines")
    void hostileLinesFinishQuickly(String description, String line) {
        assertTimeoutPreemptively(PER_LINE, () -> assertHandled(line), description);
    }

    static Stream<Arguments> hostileLines() {
        String tail = " - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1";
        return Stream.of(
                Arguments.of("host of 50k dot labels", "a.".repeat(50_000) + "a" + tail),
                Arguments.of("50k dot labels alone", "a.".repeat(50_000)),
                Arguments.of("50k numeric labels", "1.".repeat(50_000) + "1" + tail),
                Arguments.of("IPv6-like run", "fe80::".repeat(20_000) + tail),
                Arguments.of("1 MB of one character", "x".repeat(1_000_000)),
                Arguments.of("1 MB of blanks", " ".repeat(1_000_000)),
                Arguments.of("1 MB of brackets", "[".repeat(1_000_000)),
                Arguments.of("100k unclosed JSON objects", "{\"a\":".repeat(100_000)),
                Arguments.of("JSON nested past the limit", "[".repeat(10_000) + "]".repeat(10_000)),
                Arguments.of(
                        "500k character syslog host",
                        "Dec 10 07:13:43 " + "h".repeat(500_000) + " tag: x"),
                Arguments.of(
                        "100k syslog pid openings", "Dec 10 07:13:43 host " + "t[".repeat(100_000)),
                Arguments.of(
                        "100k repeated SD elements",
                        "<13>1 2026-09-14T10:15:30Z h a p m " + "[x a=\"v\"]".repeat(100_000)),
                Arguments.of(
                        "100k repeated SD params",
                        "<13>1 2026-09-14T10:15:30Z h a p m [x" + " a=\"v\"".repeat(100_000) + "]"),
                Arguments.of(
                        "unterminated SD value",
                        "<13>1 2026-09-14T10:15:30Z h a p m [x a=\"" + "\\\"".repeat(200_000)),
                Arguments.of(
                        "200k escaped quotes in a request",
                        "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \""
                                + "\\\"".repeat(200_000)
                                + "\" 200 1"),
                Arguments.of(
                        "unterminated user agent of backslashes",
                        ACCESS.substring(0, ACCESS.lastIndexOf(" \"Mozilla"))
                                + " \""
                                + "\\".repeat(200_001)));
    }

    @Test
    void longDottedClientNameIsRejectedButARealOneIsKept() {
        String tail = " - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1";

        assertTrue(ACCESS_PARSER.parse("a.".repeat(50_000) + "a" + tail).isEmpty());
        assertEquals(
                "crawl-66-249-66-1.googlebot.com",
                ACCESS_PARSER
                        .parse("crawl-66-249-66-1.googlebot.com" + tail)
                        .orElseThrow()
                        .srcIp());
    }

    @Test
    void repeatedStructuredDataParamsAreAllKept() {
        String line = "<13>1 2026-09-14T10:15:30Z h a p m [x" + " a=\"v\"".repeat(10_000) + "]";

        NormalizedEvent event = SYSLOG.parse(line).orElseThrow();

        Map<?, ?> structuredData = (Map<?, ?>) event.attributes().get("structuredData");
        Map<?, ?> params = (Map<?, ?>) structuredData.get("x");
        assertEquals(10_000, ((List<?>) params.get("a")).size());
    }

    /**
     * A file with CRLF endings split on {@code \n} alone leaves a {@code \r} on every line. That
     * must not change what the line means, only what its raw text is.
     */
    @ParameterizedTest
    @ValueSource(strings = {ACCESS, RFC5424, BSD, JSON})
    void trailingCarriageReturnDoesNotChangeTheEvent(String line) {
        for (Function<String, Optional<NormalizedEvent>> parser : PARSERS.values()) {
            Optional<NormalizedEvent> plain = parser.apply(line);
            Optional<NormalizedEvent> withCr = parser.apply(line + "\r");

            assertEquals(plain.isPresent(), withCr.isPresent(), line);
            if (plain.isPresent()) {
                assertEquals(fields(plain.get()), fields(withCr.get()), line);
                assertEquals(line + "\r", withCr.get().raw());
            }
        }
    }

    /** Every parser either declines the line or returns an event that keeps it whole. */
    private static void assertHandled(String line) {
        for (Map.Entry<String, Function<String, Optional<NormalizedEvent>>> parser :
                PARSERS.entrySet()) {
            parseSafely(parser.getValue(), line)
                    .ifPresent(
                            event ->
                                    assertEquals(
                                            line,
                                            event.raw(),
                                            () -> parser.getKey() + " changed raw"));
        }
    }

    /** Turns anything a parser throws, errors included, into a failure that names the line. */
    private static Optional<NormalizedEvent> parseSafely(
            Function<String, Optional<NormalizedEvent>> parser, String line) {
        try {
            return parser.apply(line);
        } catch (RuntimeException | StackOverflowError e) {
            throw new AssertionError(
                    e.getClass().getSimpleName() + " on: " + escape(abbreviate(line)), e);
        }
    }

    private static List<Object> fields(NormalizedEvent event) {
        return Arrays.asList(
                event.timestamp(),
                event.format(),
                event.host(),
                event.srcIp(),
                event.srcPort(),
                event.user(),
                event.method(),
                event.path(),
                event.protocol(),
                event.status(),
                event.bytes(),
                event.referrer(),
                event.userAgent(),
                event.severity(),
                event.message(),
                event.attributes());
    }

    private static String abbreviate(String line) {
        return line.length() <= 200 ? line : line.substring(0, 200) + "... (" + line.length() + ")";
    }

    private static String escape(String line) {
        StringBuilder out = new StringBuilder();
        line.chars()
                .forEach(
                        c -> {
                            if (c < 0x20 || c > 0x7E) {
                                out.append(String.format("\\u%04X", c));
                            } else {
                                out.append((char) c);
                            }
                        });
        return out.toString();
    }
}
