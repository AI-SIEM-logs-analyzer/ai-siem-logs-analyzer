package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.List;

public record AlertSummaryResponse(
        Severity severity,
        AttackType attackType,
        String summary,
        String recommendedAction,
        List<String> evidence,
        String model,
        Instant summarizedAt) {

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
