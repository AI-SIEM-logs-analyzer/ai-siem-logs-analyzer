package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SyslogParserTest {

    private static final Instant NOW = Instant.parse("2026-09-14T12:00:00Z");

    private final SyslogParser parser =
            new SyslogParser(Clock.fixed(NOW, ZoneOffset.UTC), ZoneOffset.UTC);

    // --- RFC 5424 ---------------------------------------------------------------------------

    @Test
    void rfc5424LineWithStructuredDataFillsEveryField() {
        // RFC 5424 section 6.5, example 3.
        String line =
                "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47"
                        + " [exampleSDID@32473 iut=\"3\" eventSource=\"Application\""
                        + " eventID=\"1011\"] An application event log entry...";

        NormalizedEvent event = parse(line);

        assertEquals(Instant.parse("2003-10-11T22:14:15.003Z"), event.timestamp());
        assertEquals(LogFormat.SYSLOG, event.format());
        assertEquals("mymachine.example.com", event.host());
        assertEquals(Severity.INFO, event.severity());
        assertEquals("An application event log entry...", event.message());
        assertEquals(line, event.raw());
        assertEquals("local4", event.attributes().get("facility"));
        assertEquals("notice", event.attributes().get("syslogSeverity"));
        assertEquals("evntslog", event.attributes().get("appName"));
        assertEquals("ID47", event.attributes().get("msgId"));
        // PROCID was the nil value, so it has no key at all.
        assertFalse(event.attributes().containsKey("procId"));
        assertEquals(
                Map.of(
                        "exampleSDID@32473",
                        Map.of("iut", "3", "eventSource", "Application", "eventID", "1011")),
                event.attributes().get("structuredData"));
    }

    @Test
    void rfc5424LineWithoutStructuredDataAndWithByteOrderMark() {
        // RFC 5424 section 6.5, example 1: the MSG is UTF-8 and announces it with a BOM.
        NormalizedEvent event =
                parse(
                        "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 -"
                                + " \uFEFF'su root' failed for lonvick on /dev/pts/8");

        assertEquals(Severity.CRITICAL, event.severity());
        assertEquals("auth", event.attributes().get("facility"));
        assertEquals("crit", event.attributes().get("syslogSeverity"));
        assertEquals("su", event.attributes().get("appName"));
        assertEquals("'su root' failed for lonvick on /dev/pts/8", event.message());
        assertFalse(event.attributes().containsKey("structuredData"));
    }

    @Test
    void rfc5424OffsetTimestampIsConvertedToUtc() {
        NormalizedEvent event =
                parse(
                        "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's"
                                + " time to make the do-nuts.");

        assertEquals(Instant.parse("2003-08-24T12:14:15.000003Z"), event.timestamp());
        assertEquals("192.0.2.1", event.host());
        assertEquals("8710", event.attributes().get("procId"));
        assertFalse(event.attributes().containsKey("msgId"));
        assertEquals("%% It's time to make the do-nuts.", event.message());
    }

    @Test
    void rfc5424NilTimestampFallsBackToReceiptTime() {
        NormalizedEvent event = parse("<13>1 - - - - - - boot finished");

        assertEquals(NOW, event.timestamp());
        assertNull(event.host());
        assertEquals("boot finished", event.message());
    }

    @Test
    void rfc5424WithoutMessageLeavesMessageEmpty() {
        NormalizedEvent event = parse("<13>1 2026-09-14T10:15:30Z web-01 app - - [meta@1 a=\"b\"]");

        assertNull(event.message());
        assertEquals(Map.of("meta@1", Map.of("a", "b")), event.attributes().get("structuredData"));
    }

    @Test
    void structuredDataEscapesAreDecodedAndRepeatedParamsKept() {
        NormalizedEvent event =
                parse(
                        "<13>1 2026-09-14T10:15:30Z web-01 app - -"
                                + " [origin ip=\"10.0.0.1\" ip=\"10.0.0.2\"]"
                                + "[quote text=\"say \\\"hi\\\" \\\\ [x\\] \\n\"] msg");

        assertEquals(
                Map.of(
                        "origin", Map.of("ip", List.of("10.0.0.1", "10.0.0.2")),
                        "quote", Map.of("text", "say \"hi\" \\ [x] \\n")),
                event.attributes().get("structuredData"));
        assertEquals("msg", event.message());
    }

    @Test
    void veryLongStructuredDataValueDoesNotExhaustTheStack() {
        // The sender controls this field; a recursive regex would overflow on it.
        String value = "A".repeat(200_000) + "\\\"" + "B".repeat(200_000);

        NormalizedEvent event =
                parse("<13>1 2026-09-14T10:15:30Z web-01 app - - [x@1 v=\"" + value + "\"] m");

        assertEquals(
                Map.of("x@1", Map.of("v", "A".repeat(200_000) + "\"" + "B".repeat(200_000))),
                event.attributes().get("structuredData"));
    }

    // --- RFC 3164 / BSD ---------------------------------------------------------------------

    @Test
    void bsdLineFromLinuxLogFile() {
        // /var/log/auth.log as rsyslog writes it: no priority, no year.
        NormalizedEvent event =
                parse(
                        "Sep 14 10:15:30 web-01 sshd[4242]: Failed password for root from"
                                + " 203.0.113.9 port 22 ssh2");

        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals(LogFormat.SYSLOG, event.format());
        assertEquals("web-01", event.host());
        assertEquals("sshd", event.attributes().get("appName"));
        assertEquals("4242", event.attributes().get("procId"));
        assertEquals("Failed password for root from 203.0.113.9 port 22 ssh2", event.message());
        // Without a priority the source said nothing about severity or facility.
        assertEquals(Severity.INFO, event.severity());
        assertFalse(event.attributes().containsKey("facility"));
    }

    @Test
    void bsdLineWithPriorityAndSpacePaddedDay() {
        NormalizedEvent event =
                parse("<86>Sep  4 07:05:01 web-01 CRON[99]: (root) CMD (run-parts)");

        assertEquals(Instant.parse("2026-09-04T07:05:01Z"), event.timestamp());
        assertEquals("authpriv", event.attributes().get("facility"));
        assertEquals("info", event.attributes().get("syslogSeverity"));
        assertEquals("CRON", event.attributes().get("appName"));
        assertEquals("(root) CMD (run-parts)", event.message());
    }

    @Test
    void severityFollowsThePriority() {
        assertEquals(Severity.CRITICAL, parse("<0>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.CRITICAL, parse("<1>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.CRITICAL, parse("<2>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.ERROR, parse("<3>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.WARNING, parse("<4>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.INFO, parse("<5>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.INFO, parse("<6>Sep 14 10:15:30 h a: m").severity());
        assertEquals(Severity.DEBUG, parse("<7>Sep 14 10:15:30 h a: m").severity());
    }

    @Test
    void bsdTagWithoutPid() {
        NormalizedEvent event = parse("Sep 14 10:15:30 web-01 kernel: [ 1.234] Linux version 6.8");

        assertEquals("kernel", event.attributes().get("appName"));
        assertFalse(event.attributes().containsKey("procId"));
        assertEquals("[ 1.234] Linux version 6.8", event.message());
    }

    @Test
    void bsdLineWithoutHostname() {
        NormalizedEvent event = parse("Sep 14 10:15:30 sshd[7]: Accepted publickey for alice");

        assertNull(event.host());
        assertEquals("sshd", event.attributes().get("appName"));
        assertEquals("Accepted publickey for alice", event.message());
    }

    @Test
    void bsdLineWithoutTagKeepsTheWholeMessage() {
        NormalizedEvent event = parse("Sep 14 10:15:30 fw01 Connection closed by 203.0.113.9:22");

        assertEquals("fw01", event.host());
        assertFalse(event.attributes().containsKey("appName"));
        assertEquals("Connection closed by 203.0.113.9:22", event.message());
    }

    @Test
    void bsdTimestampInTheFutureBelongsToLastYear() {
        // A December log read on 2 January.
        SyslogParser january =
                new SyslogParser(
                        Clock.fixed(Instant.parse("2027-01-02T08:00:00Z"), ZoneOffset.UTC),
                        ZoneOffset.UTC);

        Optional<NormalizedEvent> event = january.parse("Dec 31 23:59:59 web-01 app: bye");

        assertTrue(event.isPresent());
        assertEquals(Instant.parse("2026-12-31T23:59:59Z"), event.get().timestamp());
    }

    @Test
    void bsdTimestampIsReadInTheConfiguredZone() {
        SyslogParser bucharest =
                new SyslogParser(Clock.fixed(NOW, ZoneOffset.UTC), ZoneId.of("Europe/Bucharest"));

        Optional<NormalizedEvent> event = bucharest.parse("Sep 14 13:15:30 web-01 app: hi");

        assertTrue(event.isPresent());
        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.get().timestamp());
    }

    @Test
    void rsyslogHighPrecisionFileFormat() {
        // RSYSLOG_FileFormat, the default on current Debian and Ubuntu: a BSD line with an
        // RFC 3339 timestamp.
        NormalizedEvent event =
                parse(
                        "2026-09-14T13:15:30.123456+03:00 web-01 systemd[1]: Started Session 4 of"
                                + " user alice.");

        assertEquals(Instant.parse("2026-09-14T10:15:30.123456Z"), event.timestamp());
        assertEquals("web-01", event.host());
        assertEquals("systemd", event.attributes().get("appName"));
        assertEquals("1", event.attributes().get("procId"));
        assertEquals("Started Session 4 of user alice.", event.message());
    }

    // --- Network gear -----------------------------------------------------------------------

    @Test
    void ciscoIosLineWithSequenceNumberAndUnsyncedClock() {
        NormalizedEvent event =
                parse(
                        "<189>52: *Sep 14 10:15:30.123: %LINK-3-UPDOWN: Interface"
                                + " GigabitEthernet0/1, changed state to down");

        assertEquals(Instant.parse("2026-09-14T10:15:30.123Z"), event.timestamp());
        assertNull(event.host());
        assertEquals("local7", event.attributes().get("facility"));
        assertEquals("52", event.attributes().get("sequence"));
        assertEquals("%LINK-3-UPDOWN", event.attributes().get("appName"));
        assertEquals("Interface GigabitEthernet0/1, changed state to down", event.message());
    }

    @Test
    void ciscoAsaLineWithYear() {
        NormalizedEvent event =
                parse(
                        "<166>Sep 12 2025 10:15:30: %ASA-6-302013: Built outbound TCP connection"
                                + " 17 for outside:198.51.100.7/443");

        assertEquals(Instant.parse("2025-09-12T10:15:30Z"), event.timestamp());
        assertEquals("local4", event.attributes().get("facility"));
        assertEquals("%ASA-6-302013", event.attributes().get("appName"));
        assertEquals(
                "Built outbound TCP connection 17 for outside:198.51.100.7/443", event.message());
    }

    @Test
    void deviceTimezoneUtcOverridesTheConfiguredZone() {
        SyslogParser bucharest =
                new SyslogParser(Clock.fixed(NOW, ZoneOffset.UTC), ZoneId.of("Europe/Bucharest"));

        NormalizedEvent event =
                bucharest
                        .parse("<187>Sep 14 10:15:30.001 UTC: %SYS-3-CPUHOG: Task ran 2004ms")
                        .orElseThrow();

        assertEquals(Instant.parse("2026-09-14T10:15:30.001Z"), event.timestamp());
        assertFalse(event.attributes().containsKey("timezone"));
    }

    @Test
    void otherDeviceTimezoneIsKeptButNotGuessed() {
        // "EST" and "IST" each name more than one zone, so the abbreviation is recorded and the
        // configured zone is used.
        NormalizedEvent event =
                parse("<187>Sep 14 10:15:30 EET: %SYS-5-CONFIG_I: Configured from console");

        assertEquals(Instant.parse("2026-09-14T10:15:30Z"), event.timestamp());
        assertEquals("EET", event.attributes().get("timezone"));
        assertEquals("%SYS-5-CONFIG_I", event.attributes().get("appName"));
    }

    // --- Rejected lines ---------------------------------------------------------------------

    @Test
    void lineInAnotherFormatIsNotParsed() {
        assertTrue(
                parser.parse("10.0.0.7 - - [14/Sep/2026:10:15:30 +0000] \"GET / HTTP/1.1\" 200 1")
                        .isEmpty());
        assertTrue(parser.parse("{\"msg\":\"hi\"}").isEmpty());
        assertTrue(parser.parse("").isEmpty());
    }

    @Test
    void priorityAbove191IsNotParsed() {
        assertTrue(parser.parse("<192>Sep 14 10:15:30 web-01 app: m").isEmpty());
        assertTrue(parser.parse("<192>1 2026-09-14T10:15:30Z web-01 app - - - m").isEmpty());
    }

    @Test
    void impossibleDateIsNotParsed() {
        assertTrue(parser.parse("Feb 30 10:15:30 web-01 app: m").isEmpty());
        assertTrue(parser.parse("<13>1 2026-02-30T10:15:30Z web-01 app - - - m").isEmpty());
    }

    @Test
    void unsupportedRfc5424VersionIsNotParsed() {
        assertTrue(parser.parse("<13>2 2026-09-14T10:15:30Z web-01 app - - - m").isEmpty());
    }

    @Test
    void malformedStructuredDataIsNotParsed() {
        String header = "<13>1 2026-09-14T10:15:30Z web-01 app - - ";
        assertTrue(parser.parse(header + "[x@1 a=\"b\"").isEmpty(), "unterminated element");
        assertTrue(parser.parse(header + "[x@1 a=\"b]").isEmpty(), "unterminated value");
        assertTrue(parser.parse(header + "[x@1 a=b] m").isEmpty(), "unquoted value");
        assertTrue(parser.parse(header + "[] m").isEmpty(), "empty SD-ID");
        assertTrue(parser.parse(header + "[x@1]m").isEmpty(), "no space before MSG");
    }

    private NormalizedEvent parse(String line) {
        Optional<NormalizedEvent> event = parser.parse(line);
        assertTrue(event.isPresent(), () -> "expected the line to parse: " + line);
        return event.get();
    }
}
