package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Persistence behaviour of {@link Alert}, including alerts that have no rule behind them. */
@QuarkusTest
class AlertRepositoryTest {

    @Inject AlertRepository repository;
    @Inject AlertRuleRepository ruleRepository;
    @Inject LogEventRepository eventRepository;
    @Inject LogSourceRepository sourceRepository;

    private LogEvent persistedEvent(String sourceName) {
        LogSource source = new LogSource();
        source.setName(sourceName);
        source.setType(LogSourceType.ENDPOINT);
        sourceRepository.persist(source);

        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(Instant.parse("2026-08-18T12:00:00Z"));
        event.setSeverity(Severity.ERROR);
        event.setMessage("Failed password for invalid user admin");
        event.setRaw("raw log line");
        eventRepository.persist(event);
        return event;
    }

    private AlertRule persistedRule(String name) {
        AlertRule rule = new AlertRule();
        rule.setName(name);
        rule.setSeverity(Severity.CRITICAL);
        rule.setExpression("count(failed_login) > 5");
        ruleRepository.persist(rule);
        return rule;
    }

    private static Alert alert(LogEvent event, AlertRule rule) {
        Alert raised = new Alert();
        raised.setLogEvent(event);
        raised.setRule(rule);
        raised.setTitle("Possible SSH brute force");
        raised.setDetail("Six failed logins from 10.0.0.7 within one minute");
        raised.setSeverity(Severity.CRITICAL);
        return raised;
    }

    @Test
    @TestTransaction
    void persistsARuleGeneratedAlert() {
        LogEvent event = persistedEvent("endpoint-a");
        AlertRule rule = persistedRule("brute-force");
        Alert stored = alert(event, rule);

        repository.persist(stored);
        repository.flush();

        Alert found = repository.findById(stored.getId());
        assertEquals(rule.getId(), found.getRule().getId());
        assertEquals(event.getId(), found.getLogEvent().getId());
        assertEquals(Severity.CRITICAL, found.getSeverity());
        // Newly raised alerts start in the triage queue.
        assertEquals(AlertStatus.OPEN, found.getStatus());
        assertNotNull(found.getRaisedAt());
        assertNull(found.getResolvedAt());
    }

    @Test
    @TestTransaction
    void persistsAnAlertWithoutARule() {
        // The case rule_id is nullable for: an alert raised by a model has no rule behind it.
        LogEvent event = persistedEvent("endpoint-b");
        Alert stored = alert(event, null);

        repository.persist(stored);
        repository.flush();

        Alert found = repository.findById(stored.getId());
        assertNotNull(found.getId());
        assertNull(found.getRule());
    }

    @Test
    @TestTransaction
    void listsAlertsByStatus() {
        LogEvent event = persistedEvent("endpoint-c");
        Alert open = alert(event, null);
        Alert resolved = alert(event, null);
        resolved.setStatus(AlertStatus.RESOLVED);
        resolved.setResolvedAt(Instant.parse("2026-08-18T13:00:00Z"));

        repository.persist(open);
        repository.persist(resolved);
        repository.flush();

        List<Alert> stillOpen = repository.listByStatus(AlertStatus.OPEN);
        assertEquals(1, stillOpen.size());
        assertEquals(open.getId(), stillOpen.get(0).getId());
    }

    @Test
    @TestTransaction
    void listsEveryAlertRaisedForOneEvent() {
        LogEvent event = persistedEvent("endpoint-d");
        repository.persist(alert(event, null));
        repository.persist(alert(event, persistedRule("second-rule")));
        repository.flush();

        assertEquals(2, repository.listForLogEvent(event.getId()).size());
    }
}
