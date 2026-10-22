package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

@QuarkusTest
class AlertRuleTechniquesTest {

    @Inject AlertRuleRepository rules;

    private AlertRule persisted(boolean enabled, String... techniqueIds) {
        AlertRule rule = new AlertRule();
        rule.setName("techniques-" + UUID.randomUUID());
        rule.setSeverity(Severity.ERROR);
        rule.setExpression("status = 401");
        rule.setEnabled(enabled);
        rule.setTechniqueIds(List.of(techniqueIds));
        rules.persist(rule);
        rules.flush();
        return rule;
    }

    @Test
    @TestTransaction
    void readsEachRulesTechniquesInOneQuery() {
        AlertRule twoTechniques = persisted(true, "T1110.001", "T1078");
        AlertRule none = persisted(true);

        Map<Long, Set<String>> byRule =
                rules.techniqueIdsByRule(List.of(twoTechniques.getId(), none.getId()));

        assertEquals(Set.of("T1078", "T1110.001"), byRule.get(twoTechniques.getId()));
        assertFalse(byRule.containsKey(none.getId()));
    }

    @Test
    @TestTransaction
    void listsWhatEnabledRulesMapAndNothingElse() {
        persisted(true, "T1078");
        persisted(false, "T1499.004");

        Set<String> inUse = rules.techniqueIdsOfEnabledRules();

        assertTrue(inUse.contains("T1078"));

        assertTrue(inUse.contains("T1190"));
        assertFalse(inUse.contains("T1499.004"));
    }

    @Test
    @TestTransaction
    void replacingTheTechniquesRewritesTheRows() {
        AlertRule rule = persisted(true, "T1110.001");

        rule.setTechniqueIds(List.of("T1110.003"));
        rules.flush();

        assertEquals(
                Set.of("T1110.003"),
                rules.techniqueIdsByRule(List.of(rule.getId())).get(rule.getId()));
    }
}
