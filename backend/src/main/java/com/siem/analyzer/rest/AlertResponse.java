package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public record AlertResponse(
        Long id,
        String title,
        String detail,
        Severity severity,
        AlertStatus status,
        Instant raisedAt,
        Instant statusChangedAt,
        Instant resolvedAt,
        Long ruleId,
        String ruleName,
        Map<String, Object> groupKey,
        BigDecimal aggregateValue,
        Integer eventCount,
        Instant windowStart,
        Instant windowEnd,
        AlertEventResponse trigger,
        AlertSummaryResponse aiSummary,
        List<AlertTechniqueResponse> techniques) {

    public static AlertResponse from(
            Alert alert, List<AlertTechniqueResolver.ResolvedTechnique> techniques) {
        return new AlertResponse(
                alert.getId(),
                alert.getTitle(),
                alert.getDetail(),
                alert.getSeverity(),
                alert.getStatus(),
                alert.getRaisedAt(),
                alert.getStatusChangedAt(),
                alert.getResolvedAt(),
                alert.getRule() != null ? alert.getRule().getId() : null,
                alert.getRule() != null ? alert.getRule().getName() : null,
                alert.getGroupKey(),
                alert.getAggregateValue(),
                alert.getEventCount(),
                alert.getWindowStart(),
                alert.getWindowEnd(),
                AlertEventResponse.from(alert.getLogEvent()),
                AlertSummaryResponse.from(alert),
                techniques.stream().map(AlertTechniqueResponse::from).toList());
    }
}
