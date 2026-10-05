package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.parse.AccessLogParser;
import com.siem.analyzer.parse.SyslogParser;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The built-in brute-force rule, fed lines through the production parsers. */
class BruteForceLoginRuleTest {

    private final AccessLogParser accessLogs = new AccessLogParser();
    // Only the spacing between lines matters here, so the year sshd leaves out does not.
    private final SyslogParser syslog = new SyslogParser();
    private final RuleEngine engine = new RuleEngine(List.of(BruteForceLoginRule.rule()));

    /** An access-log line at 10:{@code minute}:{@code second}. */
    private NormalizedEvent http(String ip, String request, int status, int minute, int second) {
        String line =
                "%s - - [14/Sep/2026:10:%02d:%02d +0000] \"%s HTTP/1.1\" %d 512"
                        .formatted(ip, minute, second, request, status);
        return accessLogs.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    /** An auth.log line from sshd at 10:{@code minute}:{@code second}. */
    private NormalizedEvent sshd(String message, int minute, int second) {
        String line =
                "Sep 14 10:%02d:%02d web-01 sshd[4242]: %s".formatted(minute, second, message);
        return syslog.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    private NormalizedEvent failedPassword(String ip, int minute, int second) {
        return sshd("Failed password for root from " + ip + " port 50000 ssh2", minute, second);
    }

    private List<Detection> feed(List<NormalizedEvent> events) {
        return engine.evaluateAll(events);
    }

    @Test
    void storedExpressionParses() {
        DetectionRule rule = BruteForceLoginRule.rule();

        assertEquals("brute-force-login", rule.name());
        assertTrue(rule.expression().isWindowed());
    }

    @Test
    void fiveFailedSshPasswordsInAMinuteFire() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            events.add(failedPassword("203.0.113.9", 0, i * 12));
        }

        List<Detection> fired = feed(events);

        assertEquals(1, fired.size());
        Detection detection = fired.get(0);
        assertEquals(Map.of("srcIp", "203.0.113.9"), detection.group());
        assertEquals(5, detection.eventCount());
        assertEquals("count = 5 (>= 5) within 1m for srcIp=203.0.113.9", detection.summary());
    }

    @Test
    void fourFailuresAreNotEnough() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            events.add(failedPassword("203.0.113.9", 0, i));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void fiveFailuresSpreadOverMoreThanAMinuteDoNotFire() {
        // One every 15 seconds: the fifth is a full minute after the first.
        List<NormalizedEvent> events = new ArrayList<>();
        for (int seconds = 0; seconds <= 60; seconds += 15) {
            events.add(failedPassword("203.0.113.9", seconds / 60, seconds % 60));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void addressesAreCountedSeparately() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            events.add(failedPassword("203.0.113.9", 0, i));
            events.add(failedPassword("198.51.100.4", 0, i));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void invalidUserLinesAreNotCountedTwice() {
        // Each attempt on an unknown account logs both lines; four attempts are four failures.
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            events.add(sshd("Invalid user admin from 203.0.113.9 port 50000", 0, i));
            events.add(
                    sshd(
                            "Failed password for invalid user admin from 203.0.113.9 port 50000"
                                    + " ssh2",
                            0,
                            i));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void successfulAndPublicKeyLoginsAreNotFailures() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(sshd("Accepted password for alice from 203.0.113.9 port 50000 ssh2", 0, i));
            events.add(
                    sshd(
                            "Failed publickey for alice from 203.0.113.9 port 50000 ssh2: RSA"
                                    + " SHA256:abc",
                            0,
                            i));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void fiveRejectedHttpLoginsInAMinuteFire() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            events.add(http("203.0.113.9", "POST /api/auth/login", 401, 0, i * 10));
        }

        List<Detection> fired = feed(events);

        assertEquals(1, fired.size());
        assertEquals(Map.of("srcIp", "203.0.113.9"), fired.get(0).group());
    }

    @Test
    void loginLikePathsAreRecognised() {
        List<String> requests =
                List.of(
                        "POST /wp-login.php",
                        "POST /signin",
                        "POST /user/log-in",
                        "POST /oauth/token",
                        "GET /admin/Login.aspx");
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < requests.size(); i++) {
            events.add(http("203.0.113.9", requests.get(i), 403, 0, i));
        }

        assertEquals(1, feed(events).size());
    }

    @Test
    void otherRejectionsAndSuccessfulLoginsDoNotCount() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            // A 401 outside a login path, a successful login, and "login" only in the query.
            events.add(http("203.0.113.9", "GET /api/events", 401, 0, i));
            events.add(http("203.0.113.9", "POST /login", 200, 0, i));
            events.add(http("203.0.113.9", "GET /reports?next=/login", 403, 0, i));
        }

        assertEquals(List.of(), feed(events));
    }

    @Test
    void sshAndHttpFailuresFromOneAddressAddUp() {
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            events.add(failedPassword("203.0.113.9", 0, i));
        }
        events.add(http("203.0.113.9", "POST /login", 401, 0, 10));
        events.add(http("203.0.113.9", "POST /login", 401, 0, 20));

        assertEquals(1, feed(events).size());
    }
}
