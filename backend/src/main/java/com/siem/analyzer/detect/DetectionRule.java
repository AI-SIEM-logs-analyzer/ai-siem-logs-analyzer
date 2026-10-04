package com.siem.analyzer.detect;

import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import java.util.Objects;

/**
 * A rule ready for the {@link RuleEngine}: its identity plus its parsed expression.
 *
 * @param id the {@link AlertRule} this was compiled from; {@code null} for an ad-hoc rule
 * @param name unique among the rules one engine runs
 * @param severity the severity of what the rule raises
 * @param expression what the rule matches and aggregates
 */
public record DetectionRule(Long id, String name, Severity severity, RuleExpression expression) {

    public DetectionRule {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(expression, "expression");
    }

    /**
     * Compiles a stored rule.
     *
     * @throws RuleSyntaxException its expression does not parse
     */
    public static DetectionRule compile(AlertRule rule) {
        return new DetectionRule(
                rule.getId(),
                rule.getName(),
                rule.getSeverity(),
                RuleExpressionParser.parse(rule.getExpression()));
    }

    /**
     * Builds an ad-hoc rule, one with no stored {@link AlertRule} behind it.
     *
     * @throws RuleSyntaxException the expression does not parse
     */
    public static DetectionRule of(String name, Severity severity, String expression) {
        return new DetectionRule(null, name, severity, RuleExpressionParser.parse(expression));
    }
}
