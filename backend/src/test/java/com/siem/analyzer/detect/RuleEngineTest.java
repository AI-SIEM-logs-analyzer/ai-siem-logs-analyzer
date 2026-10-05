package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RuleEngineTest {

    private static final Instant T0 = Instant.parse("2026-10-04T10:00:00Z");

    private static final String BRUTE_FORCE =
            "status == 401 and path startswith \"/login\" | count by srcIp within 5m >= 5";

    private static NormalizedEvent failedLogin(String ip, long secondsAfterT0) {
        return NormalizedEvent.builder(
                        T0.plusSeconds(secondsAfterT0), LogFormat.ACCESS_LOG, "raw " + ip)
                .srcIp(ip)
                .method("POST")
                .path("/login")
                .status(401)
                .build();
    }

    private static RuleEngine engine(String expression) {
        return new RuleEngine(List.of(DetectionRule.of("rule", Severity.WARNING, expression)));
    }

    @Test
    void firesWhenTheCountReachesTheThresholdWithinTheWindow() {
        RuleEngine engine = engine(BRUTE_FORCE);

        for (int i = 0; i < 4; i++) {
            assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", i * 30L)));
        }
        List<Detection> fired = engine.evaluate(failedLogin("10.0.0.1", 120));

        assertEquals(1, fired.size());
        Detection detection = fired.get(0);
        assertEquals("rule", detection.rule().name());
        assertEquals(Map.of("srcIp", "10.0.0.1"), detection.group());
        assertEquals(0, detection.value().compareTo(BigDecimal.valueOf(5)));
        assertEquals(5, detection.eventCount());
        assertEquals(T0, detection.windowStart());
        assertEquals(T0.plusSeconds(120), detection.windowEnd());
        assertEquals("count = 5 (>= 5) within 5m for srcIp=10.0.0.1", detection.summary());
    }

    @Test
    void eventsSpreadWiderThanTheWindowNeverFire() {
        RuleEngine engine = engine(BRUTE_FORCE);

        // One failure every 80 seconds: at most four fit in any five-minute window.
        List<Detection> fired = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            fired.addAll(engine.evaluate(failedLogin("10.0.0.1", i * 80L)));
        }

        assertEquals(List.of(), fired);
    }

    @Test
    void windowExcludesAnEventExactlyOneWindowOld() {
        RuleEngine engine = engine("true | count within 1m >= 2");

        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 0)));
        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 60)));
        assertEquals(1, engine.evaluate(failedLogin("10.0.0.1", 119)).size());
    }

    @Test
    void groupsCountIndependently() {
        RuleEngine engine = engine(BRUTE_FORCE);

        List<Detection> fired = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            fired.addAll(engine.evaluate(failedLogin("10.0.0.1", i)));
            fired.addAll(engine.evaluate(failedLogin("10.0.0.2", i)));
        }
        assertEquals(List.of(), fired);

        fired.addAll(engine.evaluate(failedLogin("10.0.0.2", 10)));
        assertEquals(1, fired.size());
        assertEquals(Map.of("srcIp", "10.0.0.2"), fired.get(0).group());
    }

    @Test
    void eventsThatFailTheConditionAreNotCounted() {
        RuleEngine engine = engine(BRUTE_FORCE);
        NormalizedEvent success =
                NormalizedEvent.builder(T0, LogFormat.ACCESS_LOG, "ok")
                        .srcIp("10.0.0.1")
                        .path("/login")
                        .status(200)
                        .build();

        for (int i = 0; i < 10; i++) {
            assertEquals(List.of(), engine.evaluate(success));
        }
        assertEquals(0, engine.trackedGroups());
    }

    @Test
    void windowStartsOverAfterFiring() {
        RuleEngine engine = engine(BRUTE_FORCE);

        int fired = 0;
        for (int i = 0; i < 12; i++) {
            fired += engine.evaluate(failedLogin("10.0.0.1", i)).size();
        }

        // Fires on the 5th and the 10th, not on every event from the 5th on.
        assertEquals(2, fired);
    }

    @Test
    void stragglerFromAFiredBurstDoesNotOpenTheNextWindow() {
        RuleEngine engine = engine("true | count by srcIp within 5m >= 2");

        engine.evaluate(failedLogin("10.0.0.1", 100));
        assertEquals(1, engine.evaluate(failedLogin("10.0.0.1", 110)).size());

        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 105)));
        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 120)));
        assertEquals(1, engine.evaluate(failedLogin("10.0.0.1", 130)).size());
    }

    @Test
    void outOfOrderEventsInsideTheWindowCount() {
        RuleEngine engine = engine("true | count by srcIp within 1m >= 3");

        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 50)));
        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 30)));
        List<Detection> fired = engine.evaluate(failedLogin("10.0.0.1", 40));

        assertEquals(1, fired.size());
        assertEquals(T0.plusSeconds(30), fired.get(0).windowStart());
        assertEquals(T0.plusSeconds(50), fired.get(0).windowEnd());
    }

    @Test
    void eventOlderThanItsGroupsWindowIsDropped() {
        RuleEngine engine = engine("true | count by srcIp within 1m >= 2");

        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 300)));
        assertEquals(List.of(), engine.evaluate(failedLogin("10.0.0.1", 200)));
        assertEquals(1, engine.evaluate(failedLogin("10.0.0.1", 301)).size());
    }

    @Test
    void distinctCountsDifferentValues() {
        RuleEngine engine = engine("status == 404 | distinct(path) by srcIp within 1m > 3");

        List<Detection> fired = new ArrayList<>();
        // The same path over and over is one value, however often it is requested.
        for (int i = 0; i < 10; i++) {
            fired.addAll(engine.evaluate(notFound("10.0.0.9", "/a", i)));
        }
        assertEquals(List.of(), fired);

        fired.addAll(engine.evaluate(notFound("10.0.0.9", "/b", 11)));
        fired.addAll(engine.evaluate(notFound("10.0.0.9", "/c", 12)));
        assertEquals(List.of(), fired);
        fired.addAll(engine.evaluate(notFound("10.0.0.9", "/d", 13)));

        assertEquals(1, fired.size());
        assertEquals(0, fired.get(0).value().compareTo(BigDecimal.valueOf(4)));
        assertEquals(13, fired.get(0).eventCount());
    }

    @Test
    void distinctForgetsValuesThatLeaveTheWindow() {
        RuleEngine engine = engine("true | distinct(path) within 1m >= 3");

        engine.evaluate(notFound("10.0.0.9", "/a", 0));
        engine.evaluate(notFound("10.0.0.9", "/b", 10));
        // /a has expired by the time /c arrives, so only two distinct paths remain.
        assertEquals(List.of(), engine.evaluate(notFound("10.0.0.9", "/c", 61)));
        assertEquals(1, engine.evaluate(notFound("10.0.0.9", "/a", 62)).size());
    }

    @Test
    void sumAddsAndExpiresExactly() {
        RuleEngine engine = engine("true | sum(bytes) by srcIp within 1m > 1000");

        assertEquals(List.of(), engine.evaluate(download("10.0.0.3", 600, 0)));
        // 600 + 400 is exactly 1000: not above it.
        assertEquals(List.of(), engine.evaluate(download("10.0.0.3", 400, 30)));
        // The first 600 has expired, so this is 400 + 600 again.
        assertEquals(List.of(), engine.evaluate(download("10.0.0.3", 600, 61)));
        List<Detection> fired = engine.evaluate(download("10.0.0.3", 1, 62));

        assertEquals(1, fired.size());
        assertEquals(0, fired.get(0).value().compareTo(BigDecimal.valueOf(1001)));
    }

    @Test
    void eventsWithoutTheGroupFieldOrAggregatedFieldAreSkipped() {
        RuleEngine engine = engine("true | distinct(user) by srcIp within 1m >= 1");
        NormalizedEvent noIp =
                NormalizedEvent.builder(T0, LogFormat.PLAIN, "x").user("alice").build();
        NormalizedEvent noUser =
                NormalizedEvent.builder(T0, LogFormat.PLAIN, "x").srcIp("10.0.0.1").build();

        assertEquals(List.of(), engine.evaluate(noIp));
        assertEquals(List.of(), engine.evaluate(noUser));
        assertEquals(0, engine.trackedGroups());
    }

    @Test
    void ungroupedWindowCountsEverything() {
        RuleEngine engine = engine("status >= 500 | count within 1m >= 3");

        engine.evaluate(serverError("10.0.0.1", 0));
        engine.evaluate(serverError("10.0.0.2", 1));
        List<Detection> fired = engine.evaluate(serverError("10.0.0.3", 2));

        assertEquals(1, fired.size());
        assertEquals(Map.of(), fired.get(0).group());
    }

    @Test
    void perEventRuleFiresOnEveryMatch() {
        RuleEngine engine = engine("userAgent matches \"(?i)sqlmap\"");
        NormalizedEvent scan =
                NormalizedEvent.builder(T0, LogFormat.ACCESS_LOG, "x")
                        .userAgent("sqlmap/1.7")
                        .build();

        List<Detection> first = engine.evaluate(scan);
        List<Detection> second = engine.evaluate(scan);

        assertEquals(1, first.size());
        assertEquals(1, second.size());
        assertSame(scan, first.get(0).trigger());
        assertEquals("matched rule", first.get(0).summary());
        assertEquals(0, engine.trackedGroups());
    }

    @Test
    void everyRuleSeesEveryEvent() {
        RuleEngine engine =
                new RuleEngine(
                        List.of(
                                DetectionRule.of("any-401", Severity.INFO, "status == 401"),
                                DetectionRule.of("brute-force", Severity.CRITICAL, BRUTE_FORCE)));

        List<Detection> fired = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            fired.addAll(engine.evaluate(failedLogin("10.0.0.1", i)));
        }

        assertEquals(6, fired.size());
        assertEquals("brute-force", fired.get(5).rule().name());
        assertEquals("any-401", fired.get(4).rule().name());
    }

    @Test
    void sweepDropsGroupsThatWentQuiet() {
        RuleEngine engine = engine("true | count by srcIp within 1m >= 1000000");

        for (int i = 0; i < 100; i++) {
            engine.evaluate(failedLogin("10.0.1." + i, 0));
        }
        assertEquals(100, engine.trackedGroups());

        // Enough later traffic from one address to trigger a sweep, an hour on.
        for (int i = 0; i < RuleEngine.SWEEP_INTERVAL; i++) {
            engine.evaluate(failedLogin("10.0.2.1", 3_600));
        }

        assertEquals(1, engine.trackedGroups());
    }

    @Test
    void evaluateAllFeedsEventsInOrder() {
        RuleEngine engine = engine(BRUTE_FORCE);
        List<NormalizedEvent> events = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            events.add(failedLogin("10.0.0.1", i));
        }

        assertEquals(2, engine.evaluateAll(events).size());
    }

    @Test
    void duplicateRuleNamesAreRejected() {
        DetectionRule rule = DetectionRule.of("same", Severity.INFO, "true");

        assertThrows(IllegalArgumentException.class, () -> new RuleEngine(List.of(rule, rule)));
    }

    @Test
    void compilesAStoredRule() {
        AlertRule stored = new AlertRule();
        stored.setName("ssh-brute-force");
        stored.setSeverity(Severity.ERROR);
        stored.setExpression(BRUTE_FORCE);

        DetectionRule rule = DetectionRule.compile(stored);

        assertNull(rule.id());
        assertEquals("ssh-brute-force", rule.name());
        assertEquals(Severity.ERROR, rule.severity());
        assertTrue(rule.expression().isWindowed());
    }

    @Test
    void storedRuleWithABadExpressionDoesNotCompile() {
        AlertRule stored = new AlertRule();
        stored.setName("broken");
        stored.setSeverity(Severity.ERROR);
        stored.setExpression("status ==");

        assertThrows(RuleSyntaxException.class, () -> DetectionRule.compile(stored));
    }

    private static NormalizedEvent notFound(String ip, String path, long secondsAfterT0) {
        return NormalizedEvent.builder(T0.plusSeconds(secondsAfterT0), LogFormat.ACCESS_LOG, "x")
                .srcIp(ip)
                .path(path)
                .status(404)
                .build();
    }

    private static NormalizedEvent download(String ip, long bytes, long secondsAfterT0) {
        return NormalizedEvent.builder(T0.plusSeconds(secondsAfterT0), LogFormat.ACCESS_LOG, "x")
                .srcIp(ip)
                .status(200)
                .bytes(bytes)
                .build();
    }

    private static NormalizedEvent serverError(String ip, long secondsAfterT0) {
        return NormalizedEvent.builder(T0.plusSeconds(secondsAfterT0), LogFormat.ACCESS_LOG, "x")
                .srcIp(ip)
                .status(503)
                .build();
    }
}
