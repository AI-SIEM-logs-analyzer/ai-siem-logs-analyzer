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

/** The built-in SQL injection rule, fed request lines through the production access-log parser. */
class SqlInjectionRuleTest {

    private final AccessLogParser accessLogs = new AccessLogParser();
    private final RuleEngine engine = new RuleEngine(List.of(SqlInjectionRule.rule()));

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
        DetectionRule rule = SqlInjectionRule.rule();

        assertEquals("sql-injection", rule.name());
        assertFalse(rule.expression().isWindowed());
    }

    @Test
    void oneInjectedRequestFires() {
        List<Detection> fired = feed("/products?id=1%27%20OR%201%3D1--");

        assertEquals(1, fired.size());
        assertEquals("sql-injection", fired.get(0).rule().name());
        assertEquals("203.0.113.9", fired.get(0).trigger().srcIp());
        assertEquals("matched sql-injection", fired.get(0).summary());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Tautologies, as typed and as encoded.
                "/login?user=admin'+OR+1=1--&pass=x",
                "/login?user=admin%27%20or%20%27a%27%3D%27a",
                "/login?user=%22%20or%20%22%22%3D%22",
                "/items?id=1')+AND+('x'='x",
                "/items?id=x'||'a'+LIKE+'a",
                "/items?id=1+OR+1=1",
                "/items?id=5%20and%201%3D2",
                "/users/7%27%20OR%20%271%27%3D%271",
                // Double encoding and inline comments in place of spaces.
                "/items?id=1%2527%2520OR%25201%253D1",
                "/items?id=1'/**/OR/**/1=1",
                // UNION-based.
                "/items?id=-1+UNION+SELECT+username,password+FROM+users",
                "/items?id=-1%20union%20all%20select%20null,null--",
                "/items?id=-1/**/UNION/**/SELECT/**/1,2",
                "/items?id=-1+union(select+1)",
                // Comments that cut the query off, and column counting.
                "/login?user=admin'--",
                "/login?user=admin%27%23",
                "/items?id=1'+ORDER+BY+3--+",
                "/items?id=1%27%20group%20by%201",
                // Stacked statements.
                "/items?id=1;DROP+TABLE+users",
                "/items?id=1;%20exec%20xp_cmdshell('dir')",
                // Time-based blind.
                "/items?id=1+AND+SLEEP(5)",
                "/items?id=1;SELECT+pg_sleep(10)",
                "/items?id=1+and+benchmark(5000000,md5(1))",
                "/items?id=1;WAITFOR+DELAY+'0:0:5'--",
                // Subqueries, error- and file-based functions, catalogue names.
                "/items?id=1+AND+(SELECT+1+FROM+users)",
                "/items?id=1+and+extractvalue(1,concat(0x7e,version()))",
                "/items?id=1+UNION+SELECT+load_file('/etc/passwd')",
                "/items?id=1+into+outfile+'/tmp/x'",
                "/items?table=information_schema.tables",
                "/items?id=@@version",
            })
    void injectionsFire(String target) {
        assertEquals(1, feed(target).size(), target);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "/",
                "/products?id=42&sort=price",
                "/search?q=rock+and+roll",
                "/search?q=it%27s+a+union+of+states",
                "/search?q=don't+select+me",
                "/search?q=O%27Brien+and+sons",
                "/search?q=dogs+or+cats&page=2",
                "/theme?color='#fff'",
                "/docs/sql/order-by",
                "/static/app.min.js?v=2026-10-05",
                "/api/events?from=2026-09-14T10:00:00Z&to=2026-09-14T11:00:00Z",
                "/files/report%20(final).pdf",
                "/sleep/schedule?hours=8",
                "/path;jsessionid=ABC123",
                "/a?b=%zz%2",
            })
    void ordinaryRequestsDoNot(String target) {
        assertEquals(List.of(), feed(target), target);
    }

    @Test
    void queryIsDecodedButPathKeepsWhatTheServerLogged() {
        NormalizedEvent event = get("/items?id=1%27%20OR%201%3D1");

        assertEquals("/items?id=1%27%20OR%201%3D1", event.path());
        assertEquals("/items?id=1' OR 1=1", EventField.named("decodedPath").read(event));
    }

    @Test
    void hostileRequestsStayFast() {
        // Each pads a near-match with what the gaps and word runs consume, so a pattern that
        // backtracked would take quadratic time or worse.
        List<String> targets =
                List.of(
                        "/a?q='" + "%20".repeat(100_000) + "x",
                        "/a?q=" + "'/**/".repeat(50_000),
                        "/a?q=" + "'/*".repeat(50_000),
                        "/a?q=union" + "/**/".repeat(50_000) + "x",
                        "/a?q='or" + "+".repeat(100_000) + "a".repeat(100_000),
                        "/a?q=" + "or+1".repeat(50_000));
        for (String target : targets) {
            assertTimeoutPreemptively(Duration.ofSeconds(5), () -> feed(target));
        }
    }
}
