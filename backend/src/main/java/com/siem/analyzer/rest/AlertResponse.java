package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.Severity;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * An alert as the alerts page lists and shows it.
 *
 * @param ruleId the rule that fired; {@code null} for an alert raised without one, or whose rule
 *     has since been deleted
 * @param groupKey the group-by fields and their values, under the rule's field names; {@code null}
 *     for an ungrouped or per-event rule
 * @param aggregateValue the aggregate that crossed the rule's threshold; 1 for a per-event rule
 * @param eventCount how many events the rule's window held when it fired
 * @param windowStart the time of the oldest event in that window, inclusive
 * @param windowEnd the time of the newest event in that window, inclusive
 * @param trigger the event whose arrival raised the alert
 * @param aiSummary the latest model summary of the alert; {@code null} until one is requested
 * @param techniques the MITRE ATT&CK techniques the alert evidences, by ID; empty when neither its
 *     rule nor a model summary names one
 */
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
