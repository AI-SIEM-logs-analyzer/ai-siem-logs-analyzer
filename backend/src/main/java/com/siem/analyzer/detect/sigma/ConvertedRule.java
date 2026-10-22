package com.siem.analyzer.detect.sigma;

import com.siem.analyzer.detect.DetectionRule;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.Severity;
import java.util.Objects;
import java.util.Set;

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

    public DetectionRule toDetectionRule() {
        return DetectionRule.of(name, severity, expression);
    }

    public void applyTo(AlertRule row) {
        row.setName(name);
        row.setDescription(description);
        row.setSeverity(severity);
        row.setExpression(expression);
        row.setTechniqueIds(techniqueIds);
    }

    public boolean matches(AlertRule row) {
        return name.equals(row.getName())
                && description.equals(row.getDescription())
                && severity == row.getSeverity()
                && expression.equals(row.getExpression())
                && techniqueIds.equals(row.getTechniqueIds());
    }
}
