package com.siem.analyzer.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class GroundingTest {

    private static final AlertPrompt PROMPT = prompt();

    @Test
    void anAnswerBuiltFromTheAlertIsGrounded() {
        AlertSummary answer =
                answer(
                        List.of("10.0.0.7", "POST /login 401", "admin", "2001:db8::7"),
                        "Six failed logins for admin from 10.0.0.7 and 2001:db8::7 at 10:00:05.",
                        "Block 10.0.0.7.");

        assertEquals(List.of(), Grounding.ungrounded(answer, PROMPT));
    }

    @Test
    void evidenceTheAlertDoesNotHoldIsCaught() {
        AlertSummary answer =
                answer(List.of("10.0.0.7", "/wp-admin", "root"), "Failed logins.", "Review it.");

        assertEquals(List.of("/wp-admin", "root"), Grounding.ungrounded(answer, PROMPT));
    }

    @Test
    void anAddressTheAlertDoesNotHoldIsCaughtInTheSummaryAndTheAction() {
        AlertSummary answer =
                answer(
                        List.of("10.0.0.7"),
                        "Logins from 10.0.0.7, likely the same actor as 192.168.1.20.",
                        "Block 10.0.0.8 and 2001:db8::99 at the firewall.");

        assertEquals(
                List.of("192.168.1.20", "10.0.0.8", "2001:db8::99"),
                Grounding.ungrounded(answer, PROMPT));
    }

    @Test
    void anAddressHasToBeOneOfTheAlertsWholeNotAPieceOfOne() {
        AlertSummary answer =
                answer(
                        List.of("10.0.0.7"),
                        "Logins from 10.0.0.7 and 2001:DB8::7.",
                        "Block 10.0.0.70 and 0.0.0.7.");

        assertEquals(List.of("10.0.0.70", "0.0.0.7"), Grounding.ungrounded(answer, PROMPT));
    }

    @Test
    void findsAddressesButNotTimesVersionsOrNumbers() {
        assertEquals(
                List.of("10.0.0.7", "fe80:0:0:0:1:2:3:4", "::1"),
                Grounding.addresses(
                        "From 10.0.0.7. At 10:00:05, version 1.2.3.4.5, 1.5 MB, port 8080,"
                                + " then fe80:0:0:0:1:2:3:4 and ::1 (dead:beef)."));
        assertTrue(Grounding.addresses(null).isEmpty());
    }

    private static AlertSummary answer(List<String> evidence, String summary, String action) {
        return new AlertSummary(evidence, Severity.ERROR, AttackType.BRUTE_FORCE, summary, action);
    }

    private static AlertPrompt prompt() {
        LogEvent event = new LogEvent();
        event.setOccurredAt(Instant.parse("2026-10-01T10:00:05Z"));
        event.setSeverity(Severity.WARNING);
        event.setMessage("POST /login 401");
        event.setRaw("10.0.0.7 - admin \"POST /login HTTP/1.1\" 401");
        event.setPayload(Map.of("srcIp", "10.0.0.7", "user", "admin", "status", 401));

        LogEvent other = new LogEvent();
        other.setOccurredAt(Instant.parse("2026-10-01T10:00:01Z"));
        other.setSeverity(Severity.WARNING);
        other.setMessage("POST /login 401");
        other.setPayload(Map.of("srcIp", "2001:db8::7"));

        Alert alert = new Alert();
        alert.setTitle("brute-force-login");
        alert.setDetail("count = 6 (>= 5) within 1m for srcIp=10.0.0.7");
        alert.setSeverity(Severity.CRITICAL);
        alert.setLogEvent(event);
        return AlertPrompt.of(alert, List.of(other));
    }
}
