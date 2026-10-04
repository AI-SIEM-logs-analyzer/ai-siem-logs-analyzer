package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RuleExpressionParserTest {

    private static final Instant TS = Instant.parse("2026-10-04T10:00:00Z");

    private static NormalizedEvent.Builder event() {
        return NormalizedEvent.builder(TS, LogFormat.ACCESS_LOG, "raw line");
    }

    private static boolean matches(String expression, NormalizedEvent event) {
        return RuleExpressionParser.parse(expression).condition().test(event);
    }

    @Test
    void parsesAWindowedRule() {
        RuleExpression expression =
                RuleExpressionParser.parse(
                        "status in (401, 403) and path startswith \"/login\""
                                + " | count by srcIp, host within 5m >= 10");

        assertTrue(expression.isWindowed());
        WindowSpec window = expression.window();
        assertInstanceOf(Aggregation.Count.class, window.aggregation());
        assertEquals(
                List.of(EventField.named("srcIp"), EventField.named("host")), window.groupBy());
        assertEquals(Duration.ofMinutes(5), window.window());
        assertEquals(Operator.GE, window.thresholdOperator());
        assertEquals(0, window.threshold().compareTo(BigDecimal.TEN));
    }

    @Test
    void parsesEveryAggregationAndDurationUnit() {
        assertEquals(
                new Aggregation.DistinctCount(EventField.named("path")),
                RuleExpressionParser.parse("true | distinct(path) within 30s > 1")
                        .window()
                        .aggregation());
        assertEquals(
                new Aggregation.Sum(EventField.named("bytes")),
                RuleExpressionParser.parse("true | sum(bytes) within 2h > 1")
                        .window()
                        .aggregation());
        assertInstanceOf(
                Aggregation.Count.class,
                RuleExpressionParser.parse("true | COUNT() within 1d > 1").window().aggregation());
        assertEquals(
                Duration.ofDays(1),
                RuleExpressionParser.parse("true | count within 1d > 1").window().window());
        assertEquals(
                Duration.ofSeconds(30),
                RuleExpressionParser.parse("true | count within 30s > 1").window().window());
    }

    @Test
    void ruleWithoutAPipeIsPerEvent() {
        RuleExpression expression = RuleExpressionParser.parse("userAgent matches \"sqlmap\"");

        assertFalse(expression.isWindowed());
        assertNull(expression.window());
    }

    @Test
    void andBindsTighterThanOr() {
        String rule = "status == 500 or status == 404 and method == \"POST\"";

        assertTrue(matches(rule, event().status(500).method("GET").build()));
        assertFalse(matches(rule, event().status(404).method("GET").build()));
        assertTrue(matches(rule, event().status(404).method("POST").build()));
    }

    @Test
    void parenthesesAndNotGroup() {
        String rule = "not (status == 404 or status == 410)";

        assertTrue(matches(rule, event().status(200).build()));
        assertFalse(matches(rule, event().status(410).build()));
    }

    @Test
    void numberLiteralMatchesNumericStrings() {
        NormalizedEvent event = event().status(401).attributes(Map.of("code", "401")).build();

        assertTrue(matches("status == 401", event));
        assertTrue(matches("attributes.code == 401", event));
        assertTrue(matches("attributes.code >= 400", event));
        assertFalse(matches("attributes.code == 402", event));
    }

    @Test
    void stringComparisonsIgnoreCase() {
        NormalizedEvent event =
                event().path("/Admin/Users").severity(Severity.ERROR).method("get").build();

        assertTrue(matches("path startswith \"/admin\"", event));
        assertTrue(matches("path contains 'USERS'", event));
        assertTrue(matches("path endswith \"/users\"", event));
        assertTrue(matches("severity == \"error\"", event));
        assertTrue(matches("method in (\"post\", \"get\")", event));
    }

    @Test
    void absentFieldFailsEveryComparisonIncludingNotEqual() {
        NormalizedEvent event = event().build();

        assertFalse(matches("user == \"root\"", event));
        assertFalse(matches("user != \"root\"", event));
        assertFalse(matches("user exists", event));
        assertTrue(matches("not user exists or user != \"root\"", event));
    }

    @Test
    void matchesFindsThePatternAnywhereAndKeepsRegexEscapes() {
        NormalizedEvent event = event().userAgent("Mozilla/5.0 sqlmap/1.7.2").build();

        assertTrue(matches("userAgent matches \"(?i)SQLMAP|nikto\"", event));
        assertTrue(matches("userAgent matches \"sqlmap/\\d+\\.\\d\"", event));
        assertFalse(matches("userAgent matches \"^sqlmap\"", event));
    }

    @Test
    void attributesReachNestedAndDottedKeys() {
        NormalizedEvent event =
                event().attributes(
                                Map.of(
                                        "http",
                                        Map.of("request", Map.of("method", "PUT")),
                                        "event.action",
                                        "login",
                                        "x-forwarded-for",
                                        "203.0.113.9",
                                        "success",
                                        false))
                        .build();

        assertTrue(matches("attributes.http.request.method == \"put\"", event));
        assertTrue(matches("attributes.event.action == \"login\"", event));
        assertTrue(matches("attributes.x-forwarded-for == \"203.0.113.9\"", event));
        assertTrue(matches("attributes.success == false", event));
        assertFalse(matches("attributes.missing exists", event));
    }

    @Test
    void standardFieldNamesAreCaseInsensitive() {
        assertTrue(matches("SRCIP == \"10.0.0.1\"", event().srcIp("10.0.0.1").build()));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "",
                "status ==",
                "status = 401",
                "nosuchfield == 1",
                "path > \"a\"",
                "(status == 1",
                "status == 1 extra",
                "path matches \"[unclosed\"",
                "path == \"unterminated",
                "true | count within 5m < 10",
                "true | count within 5m",
                "true | count >= 10",
                "true | count within 5x > 1",
                "true | count within 0m > 1",
                "true | count within 1.5m > 1",
                "true | count within 5m > -1",
                "true | avg(bytes) within 5m > 1",
                "true | count by within 5m > 1",
                "status @ 1",
            })
    void rejectsMalformedExpressions(String expression) {
        assertThrows(RuleSyntaxException.class, () -> RuleExpressionParser.parse(expression));
    }

    @Test
    void errorSaysWhereAndWhat() {
        RuleSyntaxException error =
                assertThrows(
                        RuleSyntaxException.class,
                        () -> RuleExpressionParser.parse("status == 401 and colour == \"red\""));

        assertEquals(18, error.position());
        assertTrue(error.getMessage().contains("unknown field 'colour'"), error.getMessage());
    }

    @Test
    void lessThanThresholdExplainsWhy() {
        RuleSyntaxException error =
                assertThrows(
                        RuleSyntaxException.class,
                        () -> RuleExpressionParser.parse("true | count within 5m < 3"));

        assertTrue(error.getMessage().contains("rises"), error.getMessage());
    }
}
