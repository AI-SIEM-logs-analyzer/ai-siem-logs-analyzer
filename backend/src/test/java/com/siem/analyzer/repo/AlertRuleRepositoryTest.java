package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/** Persistence behaviour of {@link AlertRule}. */
@QuarkusTest
class AlertRuleRepositoryTest {

    @Inject AlertRuleRepository repository;

    private static AlertRule rule(String name) {
        AlertRule alertRule = new AlertRule();
        alertRule.setName(name);
        alertRule.setDescription("More than five failed logins from one address in a minute");
        alertRule.setSeverity(Severity.CRITICAL);
        alertRule.setExpression("severity >= WARNING and count(failed_login) > 5");
        return alertRule;
    }

    @Test
    @TestTransaction
    void persistsAndReadsBackAllFields() {
        AlertRule stored = rule("brute-force-ssh");

        repository.persist(stored);
        repository.flush();

        AlertRule found = repository.findById(stored.getId());
        assertEquals("brute-force-ssh", found.getName());
        assertEquals(Severity.CRITICAL, found.getSeverity());
        assertEquals("severity >= WARNING and count(failed_login) > 5", found.getExpression());
        assertTrue(found.isEnabled());
        assertNotNull(found.getCreatedAt());
        assertNotNull(found.getUpdatedAt());
    }

    @Test
    @TestTransaction
    void findsByRuleName() {
        repository.persist(rule("port-scan"));
        repository.flush();

        assertTrue(repository.findByName("port-scan").isPresent());
        assertTrue(repository.findByName("no-such-rule").isEmpty());
    }

    @Test
    @TestTransaction
    void listsOnlyEnabledRules() {
        AlertRule enabled = rule("enabled-rule");
        AlertRule disabled = rule("disabled-rule");
        disabled.setEnabled(false);

        repository.persist(enabled);
        repository.persist(disabled);
        repository.flush();

        assertEquals(1, repository.listEnabled().size());
        assertEquals("enabled-rule", repository.listEnabled().get(0).getName());
    }
}
