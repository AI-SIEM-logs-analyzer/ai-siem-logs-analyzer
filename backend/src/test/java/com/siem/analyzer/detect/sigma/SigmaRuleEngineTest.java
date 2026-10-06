package com.siem.analyzer.detect.sigma;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.detect.Detection;
import com.siem.analyzer.detect.RuleEngine;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.parse.AccessLogParser;
import com.siem.analyzer.parse.SyslogParser;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Converted Sigma rules run by the {@link RuleEngine} over lines read by the production parsers, so
 * the field mapping is checked against what the parsers actually fill in.
 */
class SigmaRuleEngineTest {

    private final AccessLogParser accessLogs = new AccessLogParser();
    private final SyslogParser syslog = new SyslogParser();

    private static RuleEngine engine(String yaml) {
        SigmaImport converted = SigmaConverter.withDefaults().convert(yaml);
        assertEquals(List.of(), converted.skipped());
        return new RuleEngine(
                converted.rules().stream().map(ConvertedRule::toDetectionRule).toList());
    }

    /** A combined-format request at 10:15:{@code second}. */
    private NormalizedEvent request(
            String ip, String target, int status, String agent, int second) {
        String line =
                "%s - - [14/Sep/2026:10:15:%02d +0000] \"GET %s HTTP/1.1\" %d 512 \"-\" \"%s\""
                        .formatted(ip, second, target, status, agent);
        return accessLogs.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    private NormalizedEvent sshd(String message, int second) {
        String line = "Sep 14 10:15:%02d web-01 sshd[4242]: %s".formatted(second, message);
        return syslog.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    private static final String TRAVERSAL =
            """
            title: Path Traversal Exploitation Attempts
            id: 7745c2ea-24a5-4290-b680-04359cb84b35
            logsource:
                category: webserver
            detection:
                selection:
                    cs-uri-query|contains:
                        - '../../../etc/'
                        - '%252e%252e%252fetc%252f'
                filter:
                    sc-status: 404
                condition: selection and not filter
            level: medium
            """;

    @Test
    void firesOnTheRequestTargetsItDescribes() {
        RuleEngine engine = engine(TRAVERSAL);
        String ip = "198.51.100.7";

        List<Detection> fired =
                engine.evaluateAll(
                        List.of(
                                request(ip, "/view?file=../../../etc/passwd", 200, "x", 1),
                                request(ip, "/view?f=%252e%252e%252fetc%252fhosts", 500, "x", 2),
                                // SigmaHQ's cs-uri-query means the whole target, path included.
                                request(ip, "/../../../etc/passwd", 403, "x", 3),
                                // Filtered out: the server did not have it.
                                request(ip, "/view?file=../../../etc/passwd", 404, "x", 4),
                                request(ip, "/index.html", 200, "x", 5)));

        assertEquals(
                "sigma-path-traversal-exploitation-attempts-7745c2ea", fired.get(0).rule().name());
        assertEquals(
                List.of(200, 500, 403), fired.stream().map(d -> d.trigger().status()).toList());
    }

    @Test
    void aWebserverRuleIgnoresSyslogEvenWhenItsConditionIsANegation() {
        RuleEngine engine =
                engine(
                        """
                        title: Anything but a success
                        logsource:
                            category: webserver
                        detection:
                            success:
                                sc-status: 200
                            condition: not success
                        """);

        List<Detection> fired =
                engine.evaluateAll(
                        List.of(
                                sshd(
                                        "Failed password for root from 203.0.113.9 port 50000 ssh2",
                                        1),
                                request("203.0.113.9", "/missing", 404, "x", 2),
                                request("203.0.113.9", "/", 200, "x", 3)));

        assertEquals(1, fired.size());
        assertEquals(404, fired.get(0).trigger().status());
    }

    @Test
    void aLinuxKeywordRuleReadsTheRawSyslogLine() {
        RuleEngine engine =
                engine(
                        """
                        title: SSH root login
                        logsource:
                            product: linux
                            service: sshd
                        detection:
                            keywords:
                                - 'Accepted password for root'
                            condition: keywords
                        """);

        List<Detection> fired =
                engine.evaluateAll(
                        List.of(
                                sshd("Accepted password for root from 203.0.113.9 port 1 ssh2", 1),
                                sshd("Accepted password for alice from 203.0.113.9 port 1 ssh2", 2),
                                request(
                                        "203.0.113.9",
                                        "/Accepted%20password%20for%20root",
                                        200,
                                        "x",
                                        3)));

        assertEquals(1, fired.size());
        assertEquals("root", fired.get(0).trigger().user());
    }

    @Test
    void aCorrelationCountsFailuresPerAddressWithinItsTimespan() {
        RuleEngine engine =
                engine(
                        """
                        title: Failed login
                        name: failed_login
                        logsource:
                            category: webserver
                        detection:
                            selection:
                                sc-status: [401, 403]
                                cs-uri-stem|endswith: /login
                            condition: selection
                        ---
                        title: Login brute force
                        correlation:
                            type: event_count
                            rules: failed_login
                            group-by: c-ip
                            timespan: 1m
                            condition:
                                gte: 5
                        """);

        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            events.add(request("203.0.113.9", "/login", 401, "x", i));
            events.add(request("198.51.100.1", "/login", 401, "x", i));
            events.add(request("203.0.113.9", "/login?next=/", 200, "x", i));
        }
        events.remove(events.size() - 2);

        List<Detection> fired = engine.evaluateAll(events);

        assertEquals(1, fired.size());
        assertEquals("sigma-login-brute-force", fired.get(0).rule().name());
        assertEquals("203.0.113.9", fired.get(0).group().get("srcIp"));
        assertEquals("count = 5 (>= 5) within 1m for srcIp=203.0.113.9", fired.get(0).summary());
    }
}
