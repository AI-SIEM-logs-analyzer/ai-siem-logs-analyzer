package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;

/**
 * A model's summary of an alert.
 *
 * @param severity how serious the model judged the alert; the alert's own severity stays the rule's
 * @param attackType what kind of attack it judged the alert to be
 * @param summary a few sentences for the analyst
 * @param recommendedAction the next step it proposes
 * @param model which model answered, as {@code provider/model}
 * @param summarizedAt when it answered
 */
public record AlertSummaryResponse(
        Severity severity,
        AttackType attackType,
        String summary,
        String recommendedAction,
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
                alert.getAiModel(),
                alert.getAiSummarizedAt());
    }
}
