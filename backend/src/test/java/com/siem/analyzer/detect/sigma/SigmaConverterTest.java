package com.siem.analyzer.detect.sigma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.detect.Condition;
import com.siem.analyzer.detect.RuleExpressionParser;
import com.siem.analyzer.domain.Severity;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Sigma YAML to rule-language text, rule by rule. */
class SigmaConverterTest {

    private final SigmaConverter converter = SigmaConverter.withDefaults();

    /** A webserver rule around {@code detection}, which is indented as a YAML block body. */
    private static String webserver(String detection) {
        return """
                title: Test rule
                logsource:
                    category: webserver
                detection:
                """
                + detection.indent(4);
    }

    private ConvertedRule only(String yaml) {
        SigmaImport result = converter.convert(yaml);
        assertEquals(List.of(), result.skipped());
        assertEquals(1, result.rules().size());
        return result.rules().get(0);
    }

    /** The expression for a webserver rule, without the {@code method exists and} guard. */
    private String condition(String detection) {
        String expression = only(webserver(detection)).expression();
        String guard = SigmaFieldMapping.HTTP_REQUEST + " and ";
        assertTrue(expression.startsWith(guard), expression);
        return expression.substring(guard.length());
    }

    private String skipReason(String yaml) {
        SigmaImport result = converter.convert(yaml);
        assertEquals(List.of(), result.rules());
        assertEquals(1, result.skipped().size());
        return result.skipped().get(0).reason();
    }

    // --- values and modifiers ------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource(
            delimiterString = "=>",
            quoteCharacter = '`',
            textBlock =
                    """
                    cs-method: POST => method == "POST"
                    sc-status: 404 => status == 404
                    sc-status: [401, 403] => status in (401, 403)
                    cs-method: [GET, HEAD] => method in ("GET", "HEAD")
                    cs-uri-query|contains: '../' => path contains "../"
                    cs-uri-stem|startswith: /admin => uriStem startswith "/admin"
                    cs-uri-stem|endswith: .php => uriStem endswith ".php"
                    cs-uri-stem: '*.php' => uriStem endswith ".php"
                    cs-uri-stem: '/wp-*' => uriStem startswith "/wp-"
                    cs-uri: '*passwd*' => path contains "passwd"
                    cs-uri-stem: '/admin*/login.php' => `uriStem matches "(?is)^/admin.*/login\\.php$"`
                    c-ip: '10.0.0.?' => `srcIp matches "(?is)^10\\.0\\.0\\..$"`
                    cs-uri-query|contains: 'id=\\*' => path contains "id=*"
                    cs-uri-query|contains: 'a\\b' => `path contains "a\\b"`
                    cs-uri-query|contains: 'a\\nb' => `path contains "a\\\\nb"`
                    cs-uri-stem|contains|cased: Admin => uriStem matches "Admin"
                    cs-uri-stem|cased: /Admin => uriStem matches "^/Admin$"
                    cs-user-agent|re: '^sqlmap/\\d' => `userAgent matches "^sqlmap/\\d"`
                    cs-user-agent|re|i: '^sqlmap' => userAgent matches "(?i)^sqlmap"
                    sc-bytes|gt: 1000000 => bytes > 1000000
                    sc-status|gte: 500 => status >= 500
                    sc-status|lt: 200 => status < 200
                    cs-username: null => not user exists
                    cs-referer|exists: true => referrer exists
                    cs-referer|exists: false => not referrer exists
                    cs-username: '*' => user exists
                    cs-username: '' => `(not user exists or user == "")`
                    cs-host: example.org => attributes.cs-host == "example.org"
                    url.path: /login => uriStem == "/login"
                    url.query: 'q=1' => uriQuery == "q=1"
                    """)
    void convertsOneFieldValue(String selection, String expected) {
        assertEquals(
                expected, condition("selection:\n    " + selection + "\ncondition: selection"));
    }

    @Test
    void ordsAListOfValuesAndAndsThemUnderAll() {
        assertEquals(
                "(path contains \"union\" or path contains \"select\")",
                condition(
                        """
                        selection:
                            cs-uri-query|contains: [union, select]
                        condition: selection
                        """));
        assertEquals(
                "path contains \"union\" and path contains \"select\"",
                condition(
                        """
                        selection:
                            cs-uri-query|contains|all: [union, select]
                        condition: selection
                        """));
    }

    @Test
    void andsTheFieldsOfAMappingAndOrsTheItemsOfAList() {
        assertEquals(
                "(method == \"POST\" and status == 200"
                        + " or uriStem endswith \".jsp\" and status == 404)",
                condition(
                        """
                        selection:
                            - cs-method: POST
                              sc-status: 200
                            - cs-uri-stem|endswith: .jsp
                              sc-status: 404
                        condition: selection
                        """));
    }

    @Test
    void searchesKeywordsAnywhereInTheRawLine() {
        assertEquals(
                "(raw contains \"wget http\" or raw matches \"(?is)curl.*sh\")",
                condition(
                        """
                        keywords:
                            - 'wget http'
                            - 'curl*sh'
                        condition: keywords
                        """));
    }

    @Test
    void neverTurnsKeywordsIntoAnEqualityList() {
        assertEquals(
                "(raw contains \"stack smashing detected\" or raw contains \"0bin0sh1\")",
                condition(
                        """
                        keywords:
                            - 'stack smashing detected'
                            - '0bin0sh1'
                        condition: keywords
                        """));
    }

    @Test
    void encodesBase64Values() {
        assertEquals(
                "(raw contains \"L2Jpbi9iYXNo\" or raw contains \"9iaW4vYmFza\""
                        + " or raw contains \"vYmluL2Jhc2\")",
                condition(
                        """
                        selection:
                            '|base64offset|contains': /bin/bash
                        condition: selection
                        """));
        assertEquals(
                "path contains \"d2hvYW1p\"",
                condition(
                        """
                        selection:
                            cs-uri-query|base64|contains: whoami
                        condition: selection
                        """));
    }

    @Test
    void quotedTextReadsBackExactly() {
        for (String text :
                List.of(
                        "plain",
                        "C:\\new\\temp",
                        "trailing\\",
                        "\\d+\\.\\w",
                        "say \"hi\"",
                        "it's",
                        "tab\tand\nnewline",
                        "\\\\server\\share")) {
            Condition parsed =
                    RuleExpressionParser.parse("path == " + SigmaConverter.quote(text)).condition();
            assertEquals(text, ((Condition.Compare) parsed).operand(), text);
        }
    }

    // --- conditions ----------------------------------------------------------------------------

    @Test
    void combinesSearchIdentifiers() {
        String detection =
                """
                selection_php:
                    cs-uri-stem|endswith: .php
                selection_jsp:
                    cs-uri-stem|endswith: .jsp
                filter:
                    sc-status: 404
                _helper:
                    cs-method: OPTIONS
                condition: %s
                """;
        assertEquals(
                "(uriStem endswith \".php\" or uriStem endswith \".jsp\") and not status == 404",
                condition(detection.formatted("1 of selection_* and not filter")));
        assertEquals(
                "uriStem endswith \".php\" and uriStem endswith \".jsp\" and status == 404",
                condition(detection.formatted("all of them")));
        assertEquals(
                "uriStem endswith \".php\" and not (status == 404 or method == \"OPTIONS\")",
                condition(detection.formatted("selection_php and not (filter or _helper)")));
        assertEquals(
                "(uriStem endswith \".php\" or uriStem endswith \".jsp\")",
                condition(detection.formatted("any of selection*")));
    }

    @Test
    void orsAListOfConditions() {
        assertEquals(
                "(status == 404 or method == \"PUT\")",
                condition(
                        """
                        missing:
                            sc-status: 404
                        put:
                            cs-method: PUT
                        condition:
                            - missing
                            - put
                        """));
    }

    @Test
    void turnsAnAggregationIntoAWindow() {
        String yaml =
                """
                title: Many 404s
                logsource:
                    category: webserver
                detection:
                    selection:
                        sc-status: 404
                    condition: %s
                timeframe: 1m
                """;
        assertEquals(
                "method exists and status == 404 | count by srcIp within 1m > 30",
                only(yaml.formatted("selection | count() by c-ip > 30")).expression());
        assertEquals(
                "method exists and status == 404 | distinct(uriStem) by srcIp within 1m >= 20",
                only(yaml.formatted("selection | count(cs-uri-stem) by c-ip >= 20")).expression());
        assertEquals(
                "method exists and status == 404 | sum(bytes) within 1m > 1000",
                only(yaml.formatted("selection | sum(sc-bytes) > 1000")).expression());
    }

    // --- correlations --------------------------------------------------------------------------

    private static final String FAILED_LOGIN =
            """
            title: Failed login
            name: failed_login
            logsource:
                category: webserver
            detection:
                selection:
                    sc-status: [401, 403]
                    cs-uri-stem|contains: login
                condition: selection
            ---
            title: Login brute force
            id: 0d5b2a4e-1c1e-4ad7-9d8a-6f2f1c1d0a11
            level: high
            correlation:
                type: event_count
                rules: failed_login
                group-by:
                    - c-ip
                timespan: 5m
                condition:
                    gte: 10
            """;

    @Test
    void turnsAnEventCountCorrelationIntoAWindowOverTheRulesItCounts() {
        ConvertedRule rule = only(FAILED_LOGIN);

        assertEquals("sigma-login-brute-force-0d5b2a4e", rule.name());
        assertEquals(Severity.ERROR, rule.severity());
        assertEquals(
                "method exists and status in (401, 403) and uriStem contains \"login\""
                        + " | count by srcIp within 5m >= 10",
                rule.expression());
    }

    @Test
    void importsTheCountedRulesTooWhenTheCorrelationAsks() {
        String yaml =
                FAILED_LOGIN.replace(
                        "    type: event_count", "    type: event_count\n    generate: true");

        SigmaImport result = converter.convert(yaml);

        assertEquals(List.of(), result.skipped());
        assertEquals(
                List.of("sigma-failed-login", "sigma-login-brute-force-0d5b2a4e"),
                result.rules().stream().map(ConvertedRule::name).toList());
    }

    @Test
    void countsDistinctValuesForAValueCountCorrelation() {
        String yaml =
                FAILED_LOGIN
                        .replace("type: event_count", "type: value_count")
                        .replace("timespan: 5m", "timespan: 5m\n    field: cs-username");

        assertEquals(
                "method exists and status in (401, 403) and uriStem contains \"login\""
                        + " | distinct(user) by srcIp within 5m >= 10",
                only(yaml).expression());
    }

    // --- metadata ------------------------------------------------------------------------------

    @Test
    void keepsTheRuleIdentityAndDescription() {
        ConvertedRule rule =
                only(
                        """
                        title: Path Traversal Exploitation Attempts
                        id: 7745c2ea-24a5-4290-b680-04359cb84b35
                        status: test
                        description: Detects path traversal exploitation attempts
                        references:
                            - https://github.com/projectdiscovery/nuclei-templates
                        author: Subhash Popuri, Florian Roth
                        logsource:
                            category: webserver
                        detection:
                            selection:
                                cs-uri-query|contains:
                                    - '../../../etc/'
                                    - '%252e%252e%252fetc%252f'
                            condition: selection
                        falsepositives:
                            - Internal vulnerability scanners
                        level: medium
                        """);

        assertEquals("sigma-path-traversal-exploitation-attempts-7745c2ea", rule.name());
        assertEquals("Path Traversal Exploitation Attempts", rule.title());
        assertEquals("7745c2ea-24a5-4290-b680-04359cb84b35", rule.sigmaId());
        assertEquals(Severity.WARNING, rule.severity());
        assertEquals(
                """
                Detects path traversal exploitation attempts

                Imported from Sigma rule "Path Traversal Exploitation Attempts"\
                 (7745c2ea-24a5-4290-b680-04359cb84b35) by Subhash Popuri, Florian Roth.
                False positives: Internal vulnerability scanners
                References: https://github.com/projectdiscovery/nuclei-templates""",
                rule.description());
        assertEquals(
                "method exists and (path contains \"../../../etc/\""
                        + " or path contains \"%252e%252e%252fetc%252f\")",
                rule.expression());
    }

    @ParameterizedTest
    @CsvSource({
        "informational, INFO",
        "low, INFO",
        "medium, WARNING",
        "high, ERROR",
        "critical, CRITICAL"
    })
    void mapsLevelsToSeverities(String level, Severity severity) {
        assertEquals(severity, SigmaConverter.severity(level));
    }

    @Test
    void guardsLinuxRulesToSyslog() {
        ConvertedRule rule =
                only(
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

        assertEquals(
                "format == \"SYSLOG\" and attributes.appName == \"sshd\""
                        + " and raw contains \"Accepted password for root\"",
                rule.expression());
        assertNull(rule.sigmaId());
    }

    // --- what is refused -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource(
            delimiterString = "=>",
            quoteCharacter = '`',
            textBlock =
                    """
                    c-ip|cidr: 10.0.0.0/8 => the 'cidr' modifier is not supported
                    cs-uri|wibble: x => unknown modifier 'wibble'
                    cs(Cookie): x => field 'cs(Cookie)' has no mapping
                    cs-uri|re: '(unclosed' => has an invalid regular expression
                    cs-uri|contains|startswith: x => has two match modifiers
                    cs-uri|re|contains: x => combines 're' with another match modifier
                    sc-status|gt: lots => needs a number
                    cs-referer|exists: maybe => needs true or false
                    cs-uri|i: x => regex flags without 're'
                    """)
    void refusesWhatTheEngineCannotExpress(String selection, String reason) {
        String yaml = webserver("selection:\n    " + selection + "\ncondition: selection");

        String actual = skipReason(yaml);

        assertTrue(actual.contains(reason), actual);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "selection and not missing",
                "selection | count() by c-ip < 5",
                "selection | count() by c-ip > 5 and more",
                "selection | near other",
                "(selection",
                "selection or",
                "1 of nothing*",
            })
    void refusesConditionsItCannotReadOrRun(String condition) {
        String yaml =
                webserver("selection:\n    sc-status: 404\ncondition: '" + condition + "'")
                        + "timeframe: 5m\n";

        String reason = skipReason(yaml);

        assertTrue(
                reason.contains("condition")
                        || reason.contains("aggregation")
                        || reason.contains("threshold"),
                reason);
    }

    @Test
    void refusesAnAggregationWithoutATimeframe() {
        assertEquals(
                "the aggregation has no 'timeframe' to count within",
                skipReason(
                        webserver(
                                "selection:\n    sc-status: 404\n"
                                        + "condition: selection | count() by c-ip > 5")));
    }

    @Test
    void refusesLogSourcesThisPlatformDoesNotIngest() {
        String reason =
                skipReason(
                        """
                        title: Suspicious process
                        logsource:
                            product: windows
                            category: process_creation
                        detection:
                            selection:
                                Image|endswith: '\\whoami.exe'
                            condition: selection
                        """);

        assertEquals(
                "no mapping for log source {category: process_creation, product: windows}", reason);
    }

    @Test
    void skipsDeprecatedRules() {
        String yaml =
                webserver("selection:\n    sc-status: 404\ncondition: selection")
                        + "status: deprecated\n";

        assertEquals("the rule's status is 'deprecated'", skipReason(yaml));
    }

    @Test
    void refusesACorrelationOverARuleItCannotFind() {
        String yaml = FAILED_LOGIN.replace("rules: failed_login", "rules: someone_else");

        SigmaImport result = converter.convert(yaml);

        assertEquals(
                List.of("sigma-failed-login"),
                result.rules().stream().map(ConvertedRule::name).toList());
        assertEquals(1, result.skipped().size());
        assertTrue(result.skipped().get(0).reason().contains("'someone_else'"));
    }

    @Test
    void refusesAFallingThreshold() {
        String yaml = FAILED_LOGIN.replace("gte: 10", "lt: 10");

        SigmaImport result = converter.convert(yaml);

        assertEquals(List.of(), result.rules());
        assertTrue(result.skipped().get(0).reason().startsWith("threshold 'lt' is not supported"));
    }

    @Test
    void reportsABrokenDocumentAndConvertsTheRest() {
        SigmaImport result =
                converter.convert(
                        webserver("selection:\n    sc-status: 404\ncondition: selection")
                                + "---\ntitle: Broken\nid: abc\nlogsource: {category: webserver}\n");

        assertEquals(1, result.rules().size());
        assertEquals(
                List.of(
                        new SigmaImport.Skipped(
                                "Broken", "abc", "the rule has no 'detection' mapping")),
                result.skipped());
    }

    @Test
    void refusesSigmaOneRuleCollections() {
        SigmaImport result =
                converter.convert(
                        """
                        action: global
                        title: Collection
                        logsource:
                            category: webserver
                        ---
                        detection:
                            selection:
                                sc-status: 404
                            condition: selection
                        """);

        assertEquals(List.of(), result.rules());
        assertTrue(result.skipped().get(0).reason().startsWith("Sigma 1 rule collections"));
    }

    @Test
    void refusesTextThatIsNotYaml() {
        SigmaException notYaml =
                assertThrows(SigmaException.class, () -> converter.convert("title: [unclosed"));
        assertTrue(notYaml.getMessage().startsWith("not valid YAML"), notYaml.getMessage());

        SigmaException duplicate =
                assertThrows(SigmaException.class, () -> converter.convert("title: a\ntitle: b\n"));
        assertTrue(duplicate.getMessage().contains("title"), duplicate.getMessage());

        assertThrows(SigmaException.class, () -> converter.convert("- just\n- a list\n"));
    }

    @Test
    void namesTwoRulesWithTheSameTitleAndNoIdOnlyOnce() {
        String rule = webserver("selection:\n    sc-status: 404\ncondition: selection");

        SigmaImport result = converter.convert(rule + "---\n" + rule);

        assertEquals(1, result.rules().size());
        assertEquals(
                "another rule in this import is also named sigma-test-rule",
                result.skipped().get(0).reason());
    }
}
