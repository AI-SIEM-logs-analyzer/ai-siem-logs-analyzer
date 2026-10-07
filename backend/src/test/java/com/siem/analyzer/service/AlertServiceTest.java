package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.siem.analyzer.detect.Detection;
import com.siem.analyzer.detect.DetectionRule;
import com.siem.analyzer.detect.RuleEngine;
import com.siem.analyzer.detect.RuleExpressionParser;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.repo.AlertRuleRepository;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Detections stored as alerts, and alerts moved through triage. */
@QuarkusTest
class AlertServiceTest {

    private static final Instant T0 = Instant.parse("2026-10-06T10:00:00Z");

    @Inject AlertService service;
    @Inject AlertRepository alerts;
    @Inject AlertRuleRepository rules;
    @Inject LogEventRepository events;
    @Inject LogSourceRepository sources;

    private static NormalizedEvent failedLogin(String ip, long secondsAfterT0) {
        return NormalizedEvent.builder(
                        T0.plusSeconds(secondsAfterT0), LogFormat.ACCESS_LOG, "raw " + ip)
                .srcIp(ip)
                .method("POST")
                .path("/login")
                .status(401)
                .build();
    }

    private LogEvent persistedEvent(String sourceName) {
        LogSource source = new LogSource();
        source.setName(sourceName);
        source.setType(LogSourceType.APPLICATION);
        sources.persist(source);

        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(T0);
        event.setSeverity(Severity.WARNING);
        event.setMessage("POST /login 401");
        event.setRaw("raw line");
        events.persist(event);
        return event;
    }

    private AlertRule persistedRule(String name, String expression) {
        AlertRule rule = new AlertRule();
        rule.setName(name);
        rule.setSeverity(Severity.ERROR);
        rule.setExpression(expression);
        rules.persist(rule);
        return rule;
    }

    private static Detection fire(DetectionRule rule, List<NormalizedEvent> feed) {
        List<Detection> fired = new ArrayList<>();
        RuleEngine engine = new RuleEngine(List.of(rule));
        for (NormalizedEvent event : feed) {
            fired.addAll(engine.evaluate(event));
        }
        assertEquals(1, fired.size());
        return fired.get(0);
    }

    private Alert raisedAlert(String sourceName) {
        Detection detection =
                fire(
                        DetectionRule.of("scanner", Severity.WARNING, "path startswith \"/login\""),
                        List.of(failedLogin("10.0.0.9", 0)));
        return service.raise(detection, persistedEvent(sourceName));
    }

    @Test
    @TestTransaction
    void storesAWindowedDetectionAsANewAlert() {
        AlertRule stored =
                persistedRule(
                        "test-brute-force",
                        "status == 401 and path startswith \"/login\""
                                + " | count by srcIp within 1m >= 3");
        LogEvent trigger = persistedEvent("alert-service-a");
        Detection detection =
                fire(
                        DetectionRule.compile(stored),
                        List.of(
                                failedLogin("10.0.0.7", 0),
                                failedLogin("10.0.0.7", 20),
                                failedLogin("10.0.0.7", 40)));

        Alert raised = service.raise(detection, trigger);
        alerts.flush();
        alerts.getEntityManager().clear();

        Alert found = alerts.findById(raised.getId());
        assertEquals(stored.getId(), found.getRule().getId());
        assertEquals(trigger.getId(), found.getLogEvent().getId());
        assertEquals("test-brute-force", found.getTitle());
        assertEquals("count = 3 (>= 3) within 1m for srcIp=10.0.0.7", found.getDetail());
        assertEquals(Severity.ERROR, found.getSeverity());
        assertEquals(AlertStatus.NEW, found.getStatus());
        assertEquals(Map.of("srcIp", "10.0.0.7"), found.getGroupKey());
        assertEquals(0, BigDecimal.valueOf(3).compareTo(found.getAggregateValue()));
        assertEquals(3, found.getEventCount());
        assertEquals(T0, found.getWindowStart());
        assertEquals(T0.plusSeconds(40), found.getWindowEnd());
        assertNotNull(found.getRaisedAt());
        assertNull(found.getResolvedAt());
    }

    @Test
    @TestTransaction
    void storesAPerEventDetectionFromAnAdHocRuleWithoutARule() {
        Alert raised = raisedAlert("alert-service-b");

        assertNull(raised.getRule());
        assertEquals("scanner", raised.getTitle());
        assertEquals("matched scanner", raised.getDetail());
        assertEquals(Severity.WARNING, raised.getSeverity());
        assertNull(raised.getGroupKey());
        assertEquals(1, raised.getEventCount());
        assertEquals(T0, raised.getWindowStart());
        assertEquals(T0, raised.getWindowEnd());
    }

    @Test
    @TestTransaction
    void aRuleDeletedSinceItWasCompiledLeavesTheRuleUnset() {
        DetectionRule gone =
                new DetectionRule(
                        Long.MAX_VALUE,
                        "gone",
                        Severity.INFO,
                        RuleExpressionParser.parse("status == 401"));
        Detection detection = fire(gone, List.of(failedLogin("10.0.0.8", 0)));

        Alert raised = service.raise(detection, persistedEvent("alert-service-c"));

        assertNull(raised.getRule());
        assertEquals("gone", raised.getTitle());
    }

    @Test
    @TestTransaction
    void movesAnAlertThroughTriage() {
        Long id = raisedAlert("alert-service-d").getId();

        Alert picked = service.changeStatus(id, AlertStatus.IN_PROGRESS);
        assertEquals(AlertStatus.IN_PROGRESS, picked.getStatus());
        assertNull(picked.getResolvedAt());

        Alert closed = service.changeStatus(id, AlertStatus.FALSE_POSITIVE);
        assertEquals(AlertStatus.FALSE_POSITIVE, closed.getStatus());
        assertNotNull(closed.getResolvedAt());
        assertEquals(closed.getResolvedAt(), closed.getStatusChangedAt());

        Alert reopened = service.changeStatus(id, AlertStatus.IN_PROGRESS);
        assertNull(reopened.getResolvedAt());

        Alert resolved = service.changeStatus(id, AlertStatus.RESOLVED);
        assertEquals(AlertStatus.RESOLVED, resolved.getStatus());
        assertNotNull(resolved.getResolvedAt());
    }

    @Test
    @TestTransaction
    void refusesAMoveTheLifecycleDoesNotAllow() {
        Long id = raisedAlert("alert-service-e").getId();
        service.changeStatus(id, AlertStatus.RESOLVED);

        IllegalAlertTransitionException refused =
                assertThrows(
                        IllegalAlertTransitionException.class,
                        () -> service.changeStatus(id, AlertStatus.FALSE_POSITIVE));

        assertEquals(AlertStatus.RESOLVED, refused.getFrom());
        assertEquals(AlertStatus.FALSE_POSITIVE, refused.getTo());
        assertEquals(AlertStatus.RESOLVED, alerts.findById(id).getStatus());
    }

    @Test
    @TestTransaction
    void refusesMovingToTheStatusAlreadyHeld() {
        Long id = raisedAlert("alert-service-f").getId();

        assertThrows(
                IllegalAlertTransitionException.class,
                () -> service.changeStatus(id, AlertStatus.NEW));
    }

    @Test
    @TestTransaction
    void anUnknownAlertIsNotFound() {
        assertThrows(
                NotFoundException.class,
                () -> service.changeStatus(Long.MAX_VALUE, AlertStatus.IN_PROGRESS));
    }
}
