package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.ai.AlertSummary;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import org.junit.jupiter.api.Test;

/** What {@link AlertSummaryService} accepts from a model before it stores anything. */
class AlertSummaryServiceTest {

    @Test
    void trimsTheAnswer() {
        AlertSummary usable =
                AlertSummaryService.usable(
                        1L,
                        new AlertSummary(
                                Severity.ERROR, AttackType.SQL_INJECTION, "  s \n", "\ta  "));

        assertEquals("s", usable.summary());
        assertEquals("a", usable.recommendedAction());
        assertEquals(Severity.ERROR, usable.severity());
        assertEquals(AttackType.SQL_INJECTION, usable.attackType());
    }

    @Test
    void capsARamblingAnswer() {
        AlertSummary usable =
                AlertSummaryService.usable(
                        1L,
                        new AlertSummary(
                                Severity.INFO,
                                AttackType.OTHER,
                                "s".repeat(AlertSummaryService.MAX_SUMMARY_CHARS * 2),
                                "a".repeat(AlertSummaryService.MAX_ACTION_CHARS + 1)));

        assertEquals(AlertSummaryService.MAX_SUMMARY_CHARS, usable.summary().length());
        assertTrue(usable.summary().endsWith("…"));
        assertEquals(AlertSummaryService.MAX_ACTION_CHARS, usable.recommendedAction().length());
    }

    @Test
    void refusesAnIncompleteAnswer() {
        AlertSummary[] incomplete = {
            null,
            new AlertSummary(null, AttackType.OTHER, "s", "a"),
            new AlertSummary(Severity.INFO, null, "s", "a"),
            new AlertSummary(Severity.INFO, AttackType.OTHER, null, "a"),
            new AlertSummary(Severity.INFO, AttackType.OTHER, "s", " "),
        };
        for (AlertSummary answer : incomplete) {
            assertThrows(
                    AlertSummaryFailedException.class,
                    () -> AlertSummaryService.usable(1L, answer),
                    String.valueOf(answer));
        }
    }
}
