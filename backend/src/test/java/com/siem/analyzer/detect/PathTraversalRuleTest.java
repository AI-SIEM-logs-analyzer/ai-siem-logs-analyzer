package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.parse.AccessLogParser;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The built-in path traversal rule, fed request lines through the production access-log parser. */
class PathTraversalRuleTest {

    private final AccessLogParser accessLogs = new AccessLogParser();
    private final RuleEngine engine = new RuleEngine(List.of(PathTraversalRule.rule()));

    /** An access-log line for {@code GET target}, as the server would log it. */
    private NormalizedEvent get(String target) {
        String line =
                "203.0.113.9 - - [14/Sep/2026:10:15:30 +0000] \"GET %s HTTP/1.1\" 200 512"
                        .formatted(target);
        return accessLogs.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    private List<Detection> feed(String target) {
        return engine.evaluateAll(List.of(get(target)));
    }

    @Test
    void storedExpressionParses() {
        DetectionRule rule = PathTraversalRule.rule();

        assertEquals("path-traversal", rule.name());
        assertFalse(rule.expression().isWindowed());
    }

    @Test
    void oneTraversalFires() {
        List<Detection> fired = feed("/download?file=../../../../etc/passwd");

        assertEquals(1, fired.size());
        assertEquals("path-traversal", fired.get(0).rule().name());
        assertEquals("203.0.113.9", fired.get(0).trigger().srcIp());
        assertEquals("matched path-traversal", fired.get(0).summary());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Parent segments, as typed.
                "/../../../etc/passwd",
                "/static/../../app/config.yml",
                "/download?file=../../secret.txt",
                "/download?file=..\\..\\boot.ini",
                "/img/..\\\\..\\\\web.config",
                // Filter dodges: doubled dots, Tomcat's ;, off-by-slash aliases, a bare ..
                "/download?file=....//....//app.yml",
                "/download?file=..././..././app.yml",
                "/app/..;/manager/html",
                "/app/..;jsessionid=x/admin",
                "/static../app.py",
                "/files/..",
                "/files/..?list",
                "/browse?dir=..&sort=name",
                // Percent-encoded, mixed, double- and triple-encoded.
                "/%2e%2e/%2e%2e/app.yml",
                "/download?file=%2E%2E%2F%2E%2E%2Fapp.yml",
                "/download?file=..%2fapp.yml",
                "/download?file=.%2e/app.yml",
                "/download?file=..%5capp.yml",
                "/download?file=%252e%252e%252fapp.yml",
                "/download?file=%25252e%25252e%25252fapp.yml",
                "/download?file=..%255c..%255capp.yml",
                // Overlong UTF-8, plain and double-encoded.
                "/scripts/..%c0%af../winnt/cmd.exe",
                "/%c0%ae%c0%ae/%c0%ae%c0%ae/app.yml",
                "/scripts/..%C1%9C../app.yml",
                "/x/%e0%80%ae%e0%80%ae%e0%80%afapp.yml",
                "/x/%f0%80%80%ae%f0%80%80%ae/app.yml",
                "/scripts/..%25c0%25af../app.yml",
                // IIS %u escapes and fullwidth look-alikes.
                "/download?file=%u002e%u002e%u2215app.yml",
                "/download?file=%U002E%U002E/app.yml",
                "/download?file=%ef%bc%8e%ef%bc%8e%ef%bc%8fapp.yml",
                "/download?file=..%e2%88%95app.yml",
                // A NUL byte cutting off an appended extension.
                "/view?page=index.php%00",
                "/view?page=report%2500.pdf",
                // System files, with or without the climb.
                "/etc/passwd",
                "/view?file=/etc/shadow",
                "/view?file=%2Fetc%2Fhosts",
                "/view?file=file:///etc/passwd",
                "/view?file=/proc/self/environ",
                "/view?file=/proc/1/cmdline",
                "/view?file=/home/deploy/.ssh/id_rsa",
                "/view?file=/root/.bash_history",
                "/view?file=.htpasswd",
                "/view?file=C:\\boot.ini",
                "/view?file=c:/windows/win.ini",
                "/view?file=C:%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
            })
    void traversalsFire(String target) {
        assertEquals(1, feed(target).size(), target);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "/",
                "/index.html",
                "/products?id=42&sort=price",
                "/docs/v1.2/getting-started",
                "/files/report..final.pdf",
                "/search?q=wait...what",
                "/search?q=...&page=2",
                "/a/./b/c.css",
                "/.well-known/acme-challenge/abc123",
                "/static/app.min.js?v=2026-10-05",
                "/etc-hosts-guide",
                "/blog/passwd-managers",
                "/api/proc/123/status",
                "/downloads/windows/setup.exe",
                "/search?q=caf%C3%A9+%C3%A0+la+carte",
                "/search?q=%C0+la+carte",
                "/path;jsessionid=ABC123",
                "/a?b=%zz%2",
                "/100%25useful",
            })
    void ordinaryRequestsDoNot(String target) {
        assertEquals(List.of(), feed(target), target);
    }

    @Test
    void hostileRequestsStayFast() {
        // Each pads a near-match with what the possessive runs consume, so a pattern that
        // backtracked would take quadratic time or worse.
        List<String> targets =
                List.of(
                        "/a?q=" + ".".repeat(200_000) + "x",
                        "/a?q=etc" + "/".repeat(200_000) + "x",
                        "/a?q=proc" + "/".repeat(100_000) + "1".repeat(100_000) + "x",
                        "/a?q=%" + "25".repeat(100_000) + "c0",
                        "/a?q=" + "%25".repeat(100_000),
                        "/a?q=" + "%c0".repeat(100_000));
        for (String target : targets) {
            assertTimeoutPreemptively(Duration.ofSeconds(5), () -> feed(target));
        }
    }
}
