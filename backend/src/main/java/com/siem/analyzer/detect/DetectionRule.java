package com.siem.analyzer.detect;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import java.util.Objects;

public record DetectionRule(Long id, String name, Severity severity, RuleExpression expression) {

    public DetectionRule {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(expression, "expression");
    }

    public static DetectionRule compile(AlertRule rule) {
        return new DetectionRule(
                rule.getId(),
                rule.getName(),
                rule.getSeverity(),
                RuleExpressionParser.parse(rule.getExpression()));
    }

    public static DetectionRule of(String name, Severity severity, String expression) {
        return new DetectionRule(null, name, severity, RuleExpressionParser.parse(expression));
    }
}
