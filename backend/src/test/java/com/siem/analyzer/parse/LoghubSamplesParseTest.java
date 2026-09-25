package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.service.LogFormatDetector;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Runs the parsers over real logs from Loghub, see {@code src/test/resources/loghub/README.md}.
 *
 * <p>The unit tests of each parser use lines written to exercise one rule at a time. These are
 * lines nobody wrote for us: odd tags, trailing blanks, a second space where one is expected, and
 * whole formats that look close to ours without being them.
 */
class LoghubSamplesParseTest {

    /**
     * The samples carry no year. Read in late September 2026, June and July are this year's and
     * OpenSSH's December is last year's.
     */
    private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

    private final SyslogParser syslogParser =
            new SyslogParser(Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);
    private final AccessLogParser accessParser = new AccessLogParser();
    private final JsonLogParser jsonParser =
            new JsonLogParser(
                    JsonFieldMapping.defaults(), Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);
    private final LogFormatDetector detector = new LogFormatDetector(8192);

    @ParameterizedTest
    @CsvSource({
        "Linux.log,   500, combo,                                   2026-06-29T14:44:35Z,"
                + " 2026-07-09T12:16:51Z",
        "OpenSSH.log, 500, LabSZ,                                   2025-12-10T06:55:46Z,"
                + " 2025-12-10T09:12:37Z",
        "Mac.log,     500, calvisitor-[0-9-]+|authorMacBook-Pro,    2026-07-01T09:00:55Z,"
                + " 2026-07-03T13:48:22Z"
    })
    void everySyslogSampleLineParsesInOrder(
            String file, int lineCount, String hostPattern, Instant first, Instant last)
            throws IOException {
        List<String> lines = sample(file);
        assertEquals(lineCount, lines.size());

        Instant previous = first;
        for (String line : lines) {
            NormalizedEvent event =
                    syslogParser
                            .parse(line)
                            .orElseThrow(() -> new AssertionError("unparsed: " + line));

            assertEquals(LogFormat.SYSLOG, event.format(), line);
            assertEquals(line, event.raw());
            assertNotNull(event.host(), line);
            assertTrue(event.host().matches(hostPattern), line);
            assertNotNull(event.message(), line);
            // A file written by the local daemon has no <PRI>, so nothing says how severe it is.
            assertEquals(Severity.INFO, event.severity(), line);
            assertFalse(event.attributes().containsKey("facility"), line);

            assertFalse(event.timestamp().isBefore(previous), "out of order: " + line);
            assertFalse(event.timestamp().isAfter(last), "after the sample: " + line);
            previous = event.timestamp();
        }
        assertEquals(first, syslogParser.parse(lines.getFirst()).orElseThrow().timestamp());
        assertEquals(last, previous);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "Apache.log",
                "BGL.log",
                "HDFS.log",
                "OpenStack.log",
                "Proxifier.log",
                "Thunderbird.log"
            })
    void formatsWeDoNotReadAreRejectedByEveryParser(String file) throws IOException {
        List<String> lines = sample(file);
        assertEquals(50, lines.size());

        for (String line : lines) {
            assertTrue(syslogParser.parse(line).isEmpty(), "syslog accepted: " + line);
            assertTrue(accessParser.parse(line).isEmpty(), "access log accepted: " + line);
            assertTrue(jsonParser.parse(line).isEmpty(), "json accepted: " + line);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "Linux.log, SYSLOG",
        "OpenSSH.log, SYSLOG",
        "Mac.log, SYSLOG",
        // An Apache error log is not an access log, whatever the server's name suggests.
        "Apache.log, PLAIN",
        "BGL.log, PLAIN",
        "HDFS.log, PLAIN",
        "OpenStack.log, PLAIN",
        "Proxifier.log, PLAIN",
        "Thunderbird.log, PLAIN"
    })
    void detectorSniffsEachSample(String file, LogFormat expected) {
        assertEquals(expected, detector.detect(resource(file), file));
    }

    @Test
    void failedSshPasswordKeepsTagPidAndMessage() throws IOException {
        NormalizedEvent event = parse("OpenSSH.log", 29);

        assertEquals(Instant.parse("2025-12-10T07:13:43Z"), event.timestamp());
        assertEquals("LabSZ", event.host());
        assertEquals("Failed password for root from 5.36.59.76 port 42393 ssh2", event.message());
        assertEquals(Map.of("appName", "sshd", "procId", "24227"), event.attributes());
    }

    @Test
    void bracketsInTheMessageAreNotReadAsAPid() throws IOException {
        NormalizedEvent event = parse("OpenSSH.log", 30);

        assertEquals(
                "message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393"
                        + " ssh2]",
                event.message());
        assertEquals(Map.of("appName", "sshd", "procId", "24227"), event.attributes());
    }

    @Test
    void pamSubsystemInParenthesesStaysPartOfTheTag() throws IOException {
        NormalizedEvent event = parse("Linux.log", 3);

        assertEquals("combo", event.host());
        assertEquals("session opened for user cyrus by (uid=0)", event.message());
        assertEquals(Map.of("appName", "su(pam_unix)", "procId", "17407"), event.attributes());
    }

    @Test
    void trailingBlankIsTrimmedFromTheMessageButKeptInRaw() throws IOException {
        List<String> lines = sample("Linux.log");
        String line = lines.getFirst();
        assertTrue(line.endsWith(" "), "the sample line has a trailing blank");

        NormalizedEvent event = syslogParser.parse(line).orElseThrow();

        assertEquals(
                "connection from 210.223.97.117 () at Wed Jun 29 14:44:35 2005", event.message());
        assertEquals(line, event.raw());
        assertEquals(Map.of("appName", "ftpd", "procId", "15920"), event.attributes());
    }

    @Test
    void lineWithoutATagKeepsEverythingInTheMessage() throws IOException {
        // "syslogd 1.4.1" is followed by neither '[' nor ':', so it cannot be a tag.
        NormalizedEvent restart = parse("Linux.log", 214);
        assertEquals("combo", restart.host());
        assertEquals("syslogd 1.4.1: restart.", restart.message());
        assertEquals(Map.of(), restart.attributes());

        // Two spaces after the host: the tag slot is empty, and nothing is dropped.
        NormalizedEvent login = parse("Linux.log", 399);
        assertEquals("combo", login.host());
        assertEquals("-- root[2421]: ROOT LOGIN ON tty2", login.message());
        assertEquals(Map.of(), login.attributes());
    }

    @Test
    void macTagFollowedByAParentheticalIsKeptInTheMessage() throws IOException {
        NormalizedEvent event = parse("Mac.log", 36);

        assertEquals("calvisitor-10-105-160-95", event.host());
        assertEquals(
                "sandboxd[129] ([31211]): com.apple.Addres(31211) deny network-outbound"
                        + " /private/var/run/mDNSResponder",
                event.message());
        assertEquals(Map.of(), event.attributes());
    }

    @Test
    void longMacLineParsesWhole() throws IOException {
        String line = sample("Mac.log").get(226);
        assertEquals(967, line.length());

        NormalizedEvent event = syslogParser.parse(line).orElseThrow();

        assertEquals("calvisitor-10-105-163-202", event.host());
        assertTrue(line.endsWith(event.message()), event.message());
    }

    @Test
    void kernelLineWithPidZero() throws IOException {
        NormalizedEvent event = parse("Mac.log", 1);

        assertEquals(Instant.parse("2026-07-01T09:00:55Z"), event.timestamp());
        assertEquals(Map.of("appName", "kernel", "procId", "0"), event.attributes());
        assertTrue(event.message().startsWith("IOThunderboltSwitch<0>(0x0)::listenerCallback"));
    }

    /** Parses the line with the given 1-based number, as an editor would show it. */
    private NormalizedEvent parse(String file, int lineNumber) throws IOException {
        String line = sample(file).get(lineNumber - 1);
        return syslogParser
                .parse(line)
                .orElseThrow(() -> new AssertionError(file + ":" + lineNumber + " unparsed"));
    }

    static List<String> sample(String file) throws IOException {
        return Files.readAllLines(resource(file));
    }

    private static Path resource(String file) {
        URL url = LoghubSamplesParseTest.class.getResource("/loghub/" + file);
        assertNotNull(url, file);
        try {
            return Path.of(url.toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
