package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.ai.AlertPrompt;
import com.siem.analyzer.ai.AlertSummary;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.Severity;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** What {@link AlertSummaryService} accepts from a model before it stores anything. */
class AlertSummaryServiceTest {

    private static final List<String> EVIDENCE = List.of("10.0.0.7");

    @Test
    void trimsTheAnswer() {
        AlertSummary usable =
                AlertSummaryService.usable(
                        1L,
                        new AlertSummary(
                                List.of(" 10.0.0.7 \n"),
                                Severity.ERROR,
                                AttackType.SQL_INJECTION,
                                "  s \n",
                                "\ta  "));

        assertEquals("s", usable.summary());
        assertEquals("a", usable.recommendedAction());
        assertEquals(List.of("10.0.0.7"), usable.evidence());
        assertEquals(Severity.ERROR, usable.severity());
        assertEquals(AttackType.SQL_INJECTION, usable.attackType());
    }

    @Test
    void capsARamblingAnswer() {
        AlertSummary usable =
                AlertSummaryService.usable(
                        1L,
                        new AlertSummary(
                                EVIDENCE,
                                Severity.INFO,
                                AttackType.OTHER,
                                "s".repeat(AlertSummaryService.MAX_SUMMARY_CHARS * 2),
                                "a".repeat(AlertSummaryService.MAX_ACTION_CHARS + 1)));

        assertEquals(AlertSummaryService.MAX_SUMMARY_CHARS, usable.summary().length());
        assertTrue(usable.summary().endsWith("…"));
        assertEquals(AlertSummaryService.MAX_ACTION_CHARS, usable.recommendedAction().length());
    }

    @Test
    void keepsAFewDistinctEvidenceValuesEachAVerbatimPiece() {
        List<String> evidence = new ArrayList<>(Arrays.asList("a", " a ", "", null, "  "));
        evidence.add("x".repeat(AlertSummaryService.MAX_EVIDENCE_CHARS + 10));
        for (int i = 0; i < AlertSummaryService.MAX_EVIDENCE * 2; i++) {
            evidence.add("v" + i);
        }

        List<String> kept =
                AlertSummaryService.usable(
                                1L,
                                new AlertSummary(
                                        evidence, Severity.INFO, AttackType.OTHER, "s", "a"))
                        .evidence();

        assertEquals(AlertSummaryService.MAX_EVIDENCE, kept.size());
        assertEquals("a", kept.get(0));
        // Cut without a marker, so what is kept is still a piece of the alert.
        assertEquals("x".repeat(AlertSummaryService.MAX_EVIDENCE_CHARS), kept.get(1));
        assertEquals("v0", kept.get(2));
    }

    @Test
    void refusesAnIncompleteAnswer() {
        AlertSummary[] incomplete = {
            null,
            new AlertSummary(EVIDENCE, null, AttackType.OTHER, "s", "a"),
            new AlertSummary(EVIDENCE, Severity.INFO, null, "s", "a"),
            new AlertSummary(EVIDENCE, Severity.INFO, AttackType.OTHER, null, "a"),
            new AlertSummary(EVIDENCE, Severity.INFO, AttackType.OTHER, "s", " "),
            new AlertSummary(null, Severity.INFO, AttackType.OTHER, "s", "a"),
            new AlertSummary(List.of(), Severity.INFO, AttackType.OTHER, "s", "a"),
            new AlertSummary(List.of(" "), Severity.INFO, AttackType.OTHER, "s", "a"),
        };
        for (AlertSummary answer : incomplete) {
            assertThrows(
                    AlertSummaryFailedException.class,
                    () -> AlertSummaryService.usable(1L, answer),
                    String.valueOf(answer));
        }
    }

    @Test
    void passesAGroundedAnswer() {
        AlertSummary answer =
                new AlertSummary(
                        List.of("10.0.0.7", "POST /login 401"),
                        Severity.ERROR,
                        AttackType.BRUTE_FORCE,
                        "Failed logins from 10.0.0.7.",
                        "Block 10.0.0.7.");

        assertSame(answer, AlertSummaryService.grounded(1L, answer, prompt()));
    }

    @Test
    void refusesAnAnswerThatCitesWhatTheAlertDoesNotHold() {
        AlertSummary invented =
                new AlertSummary(
                        List.of("10.0.0.7"),
                        Severity.ERROR,
                        AttackType.BRUTE_FORCE,
                        "Failed logins from 10.0.0.7.",
                        "Block 10.0.0.9.");

        AlertSummaryFailedException failure =
                assertThrows(
                        AlertSummaryFailedException.class,
                        () -> AlertSummaryService.grounded(1L, invented, prompt()));
        assertTrue(failure.isUngrounded());
        // The model's words stay in the log, not in what the caller is told.
        assertFalse(failure.getMessage().contains("10.0.0.9"), failure.getMessage());
    }

    @Test
    void anEventIsInTheGroupWhenEveryGroupFieldMatches() {
        LogEvent event = new LogEvent();
        event.setSeverity(Severity.WARNING);
        event.setPayload(
                Map.of("srcIp", "10.0.0.7", "status", 401, "attributes", Map.of("tenant", "t1")));

        assertTrue(AlertSummaryService.inGroup(event, Map.of()));
        assertTrue(AlertSummaryService.inGroup(event, Map.of("srcIp", "10.0.0.7")));
        assertTrue(AlertSummaryService.inGroup(event, Map.of("srcIp", "10.0.0.7", "status", 401)));
        assertTrue(AlertSummaryService.inGroup(event, Map.of("severity", "WARNING")));
        assertTrue(AlertSummaryService.inGroup(event, Map.of("attributes.tenant", "t1")));
        assertFalse(AlertSummaryService.inGroup(event, Map.of("srcIp", "10.0.0.8")));
        assertFalse(AlertSummaryService.inGroup(event, Map.of("user", "alice")));
        assertFalse(AlertSummaryService.inGroup(event, Map.of("attributes.tenant", "t2")));
    }

    private static AlertPrompt prompt() {
        LogEvent event = new LogEvent();
        event.setMessage("POST /login 401");
        event.setRaw("10.0.0.7 POST /login 401");
        Alert alert = new Alert();
        alert.setTitle("brute-force-login");
        alert.setLogEvent(event);
        return AlertPrompt.of(alert, List.of());
    }
}
