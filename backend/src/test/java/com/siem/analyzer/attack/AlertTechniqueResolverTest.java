package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.repo.AlertRuleRepository;
import com.siem.analyzer.repo.LogEventRepository;
import com.siem.analyzer.repo.LogSourceRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** An alert's techniques: its rule's, or the model's attack type's when no rule fired. */
@QuarkusTest
class AlertTechniqueResolverTest {

    @Inject AlertTechniqueResolver resolver;
    @Inject AlertRepository alerts;
    @Inject AlertRuleRepository rules;
    @Inject LogEventRepository events;
    @Inject LogSourceRepository sources;

    private LogEvent event() {
        LogSource source = new LogSource();
        source.setName("resolver-" + UUID.randomUUID());
        source.setType(LogSourceType.APPLICATION);
        sources.persist(source);
        LogEvent event = new LogEvent();
        event.setSource(source);
        event.setOccurredAt(Instant.parse("2026-10-01T10:00:00Z"));
        event.setSeverity(Severity.WARNING);
        event.setMessage("POST /login 401");
        event.setRaw("raw");
        events.persist(event);
        return event;
    }

    private Alert alert(LogEvent event, AlertRule rule) {
        Alert alert = new Alert();
        alert.setLogEvent(event);
        alert.setRule(rule);
        alert.setTitle("t");
        alert.setSeverity(Severity.WARNING);
        return alert;
    }

    private AlertRule rule(String... techniqueIds) {
        AlertRule rule = new AlertRule();
        rule.setName("resolver-" + UUID.randomUUID());
        rule.setSeverity(Severity.ERROR);
        rule.setExpression("status = 401");
        rule.setTechniqueIds(List.of(techniqueIds));
        rules.persist(rule);
        return rule;
    }

    @Test
    @TestTransaction
    void namesTheRulesTechniquesFromTheDataset() {
        Alert raised = alert(event(), rule("T1110.001"));
        alerts.persist(raised);

        List<AlertTechniqueResolver.ResolvedTechnique> techniques = resolver.resolve(raised);

        assertEquals(1, techniques.size());
        AlertTechniqueResolver.ResolvedTechnique guessing = techniques.get(0);
        assertEquals("T1110.001", guessing.id());
        assertEquals("Password Guessing", guessing.name());
        assertEquals("https://attack.mitre.org/techniques/T1110/001", guessing.url());
        assertEquals(
                List.of(new AlertTechniqueResolver.TacticRef("TA0006", "Credential Access")),
                guessing.tactics());
        assertEquals(TechniqueSource.RULE, guessing.source());
    }

    @Test
    @TestTransaction
    void showsAnIdTheDatasetDoesNotKnowBare() {
        Alert raised = alert(event(), rule("T1499.004", "T1110.001"));
        alerts.persist(raised);

        List<AlertTechniqueResolver.ResolvedTechnique> techniques = resolver.resolve(raised);

        assertEquals(
                List.of("T1110.001", "T1499.004"), techniques.stream().map(t -> t.id()).toList());
        AlertTechniqueResolver.ResolvedTechnique unknown = techniques.get(1);
        assertNull(unknown.name());
        assertNull(unknown.url());
        assertEquals(List.of(), unknown.tactics());
    }

    @Test
    @TestTransaction
    void fallsBackToTheModelsAttackTypeWhenNoRuleFired() {
        Alert modelled = alert(event(), null);
        modelled.recordAiSummary(
                Severity.ERROR,
                AttackType.CREDENTIAL_STUFFING,
                "s",
                "a",
                List.of(),
                "test/model",
                Instant.now());
        alerts.persist(modelled);

        List<AlertTechniqueResolver.ResolvedTechnique> techniques = resolver.resolve(modelled);

        assertEquals(1, techniques.size());
        assertEquals("T1110.004", techniques.get(0).id());
        assertEquals("Credential Stuffing", techniques.get(0).name());
        assertEquals(TechniqueSource.AI, techniques.get(0).source());
    }

    @Test
    @TestTransaction
    void anAlertWithNeitherARuleNorASummaryHasNoTechnique() {
        Alert bare = alert(event(), null);
        alerts.persist(bare);

        assertEquals(List.of(), resolver.resolve(bare));
    }

    @Test
    @TestTransaction
    void resolvesAWholePageAtOnce() {
        LogEvent event = event();
        AlertRule shared = rule("T1190");
        Alert first = alert(event, shared);
        Alert second = alert(event, shared);
        Alert third = alert(event, rule("T1083"));
        alerts.persist(first);
        alerts.persist(second);
        alerts.persist(third);

        Map<Long, List<AlertTechniqueResolver.ResolvedTechnique>> byAlert =
                resolver.resolve(List.of(first, second, third));

        assertEquals("T1190", byAlert.get(first.getId()).get(0).id());
        assertEquals("T1190", byAlert.get(second.getId()).get(0).id());
        assertEquals("T1083", byAlert.get(third.getId()).get(0).id());
    }
}
