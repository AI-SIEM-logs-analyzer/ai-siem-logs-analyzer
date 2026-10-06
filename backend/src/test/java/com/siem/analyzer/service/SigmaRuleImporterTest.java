package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.AlertRuleRepository;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Sigma rules stored as {@code alert_rule} rows. */
@QuarkusTest
class SigmaRuleImporterTest {

    private static final String NAME = "sigma-source-code-enumeration-953d460b";

    private static final String RULE =
            """
            title: Source Code Enumeration
            id: 953d460b-f810-420a-97a2-cfca4c98e602
            description: Detects requests for a version control directory
            logsource:
                category: webserver
            detection:
                keywords:
                    - '.git/'
                condition: keywords
            level: medium
            """;

    @Inject SigmaRuleImporter importer;

    @Inject AlertRuleRepository repository;

    @Test
    @TestTransaction
    void storesAConvertedRuleEnabled() {
        SigmaRuleImporter.Result result = importer.importRules(RULE);

        assertEquals(List.of(NAME), result.created());
        assertEquals(List.of(), result.skipped());
        AlertRule row = repository.findByName(NAME).orElseThrow();
        assertEquals("method exists and raw contains \".git/\"", row.getExpression());
        assertEquals(Severity.WARNING, row.getSeverity());
        assertTrue(row.getDescription().startsWith("Detects requests for a version control"));
        assertTrue(row.isEnabled());
    }

    @Test
    @TestTransaction
    void importingTheSameRuleAgainChangesNothing() {
        importer.importRules(RULE);

        SigmaRuleImporter.Result again = importer.importRules(RULE);

        assertEquals(List.of(), again.created());
        assertEquals(List.of(), again.updated());
        assertEquals(List.of(NAME), again.unchanged());
    }

    @Test
    @TestTransaction
    void aRevisedRuleUpdatesItsRowAndLeavesItDisabled() {
        importer.importRules(RULE);
        repository.findByName(NAME).orElseThrow().setEnabled(false);
        repository.flush();

        SigmaRuleImporter.Result revised =
                importer.importRules(RULE.replace("level: medium", "level: high"));

        assertEquals(List.of(NAME), revised.updated());
        AlertRule row = repository.findByName(NAME).orElseThrow();
        assertEquals(Severity.ERROR, row.getSeverity());
        assertFalse(row.isEnabled());
    }

    @Test
    @TestTransaction
    void reportsWhatItCannotConvertAndStoresTheRest() {
        long before = repository.count();

        SigmaRuleImporter.Result result =
                importer.importRules(
                        RULE
                                + """
                                ---
                                title: Windows only
                                logsource:
                                    product: windows
                                detection:
                                    selection:
                                        EventID: 4625
                                    condition: selection
                                """);

        assertEquals(List.of(NAME), result.created());
        assertEquals(1, result.skipped().size());
        assertEquals("Windows only", result.skipped().get(0).title());
        assertEquals(before + 1, repository.count());
    }
}
