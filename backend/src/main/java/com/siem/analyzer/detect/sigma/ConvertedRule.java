package com.siem.analyzer.detect.sigma;

import com.siem.analyzer.detect.DetectionRule;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import java.util.Objects;
import java.util.Set;

/**
 * A Sigma rule in this engine's terms: the fields of an {@code alert_rule} row.
 *
 * @param name {@code sigma-<title>-<id prefix>}, unique and stable across re-imports of the rule
 * @param title the Sigma title
 * @param sigmaId the Sigma {@code id}; {@code null} when the rule has none
 * @param severity from the Sigma {@code level}
 * @param description the Sigma description, followed by where the rule came from
 * @param expression rule-language text, known to parse
 * @param techniqueIds the ATT&CK techniques the rule's {@code attack.t…} tags name
 */
public record ConvertedRule(
        String name,
        String title,
        String sigmaId,
        Severity severity,
        String description,
        String expression,
        Set<String> techniqueIds) {

    public ConvertedRule {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(description, "description");
        Objects.requireNonNull(expression, "expression");
        techniqueIds = Set.copyOf(Objects.requireNonNull(techniqueIds, "techniqueIds"));
    }

    /** The rule ready for a {@link com.siem.analyzer.detect.RuleEngine}, with no stored row. */
    public DetectionRule toDetectionRule() {
        return DetectionRule.of(name, severity, expression);
    }

    /**
     * Writes this rule into a stored row: name, description, severity, expression and ATT&CK
     * techniques. Whether the row is enabled is an operator's decision and is left as it is.
     */
    public void applyTo(AlertRule row) {
        row.setName(name);
        row.setDescription(description);
        row.setSeverity(severity);
        row.setExpression(expression);
        row.setTechniqueIds(techniqueIds);
    }

    /** Whether {@code row} already holds exactly what {@link #applyTo} would write. */
    public boolean matches(AlertRule row) {
        return name.equals(row.getName())
                && description.equals(row.getDescription())
                && severity == row.getSeverity()
                && expression.equals(row.getExpression())
                && techniqueIds.equals(row.getTechniqueIds());
    }
}
