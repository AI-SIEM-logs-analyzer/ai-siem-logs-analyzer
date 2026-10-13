package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.List;

/**
 * A model's summary of an alert.
 *
 * @param severity how serious the model judged the alert; the alert's own severity stays the rule's
 * @param attackType what kind of attack it judged the alert to be
 * @param summary a few sentences for the analyst
 * @param recommendedAction the next step it proposes
 * @param evidence the values from the alert it rested its reading on, each checked to be in the
 *     alert; empty for a summary stored before evidence was asked for
 * @param model which model answered, as {@code provider/model}
 * @param summarizedAt when it answered
 */
public record AlertSummaryResponse(
        Severity severity,
        AttackType attackType,
        String summary,
        String recommendedAction,
        List<String> evidence,
        String model,
        Instant summarizedAt) {

    /** The alert's summary, or {@code null} when no model has summarised it yet. */
    public static AlertSummaryResponse from(Alert alert) {
        if (alert.getAiSummarizedAt() == null) {
            return null;
        }
        return new AlertSummaryResponse(
                alert.getAiSeverity(),
                alert.getAiAttackType(),
                alert.getAiSummary(),
                alert.getAiRecommendedAction(),
                alert.getAiEvidence() == null ? List.of() : List.copyOf(alert.getAiEvidence()),
                alert.getAiModel(),
                alert.getAiSummarizedAt());
    }
}
