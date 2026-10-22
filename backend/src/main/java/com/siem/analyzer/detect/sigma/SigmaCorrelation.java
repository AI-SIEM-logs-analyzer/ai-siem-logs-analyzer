package com.siem.analyzer.detect.sigma;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record SigmaCorrelation(
        SigmaRule.Meta meta,
        String type,
        List<String> rules,
        List<String> groupBy,
        String timespan,
        String thresholdOperator,
        BigDecimal threshold,
        String field,
        boolean generate) {

    public SigmaCorrelation {
        Objects.requireNonNull(meta, "meta");
        Objects.requireNonNull(type, "type");
        rules = List.copyOf(rules);
        groupBy = List.copyOf(groupBy);
        Objects.requireNonNull(thresholdOperator, "thresholdOperator");
        Objects.requireNonNull(threshold, "threshold");
    }

    static SigmaCorrelation from(Map<String, Object> document) {
        SigmaRule.Meta meta = SigmaRule.Meta.from(document);
        if (!(document.get("correlation") instanceof Map<?, ?> block)) {
            throw new SigmaException("'correlation' is not a mapping");
        }
        Map<String, Object> correlation = SigmaYaml.stringKeys(block);

        String type = SigmaRule.text(correlation, "type");
        if (type == null) {
            throw new SigmaException("the correlation has no 'type'");
        }
        List<String> rules = SigmaRule.texts(correlation, "rules");
        if (rules.isEmpty()) {
            throw new SigmaException("the correlation names no 'rules'");
        }
        if (correlation.containsKey("aliases")) {
            throw new SigmaException("correlation 'aliases' are not supported");
        }

        if (!(correlation.get("condition") instanceof Map<?, ?> conditionBlock)
                || conditionBlock.size() != 1) {
            throw new SigmaException(
                    "the correlation 'condition' must be one comparison, such as {gte: 10}");
        }
        Map.Entry<?, ?> comparison = conditionBlock.entrySet().iterator().next();
        BigDecimal threshold = SigmaConverter.decimal(comparison.getValue());
        if (threshold == null) {
            throw new SigmaException("the correlation threshold is not a number");
        }

        Object generate = correlation.get("generate");
        if (generate != null && !(generate instanceof Boolean)) {
            throw new SigmaException("'generate' is not true or false");
        }
        return new SigmaCorrelation(
                meta,
                type,
                rules,
                SigmaRule.texts(correlation, "group-by"),
                SigmaRule.text(correlation, "timespan"),
                String.valueOf(comparison.getKey()),
                threshold,
                SigmaRule.text(correlation, "field"),
                Boolean.TRUE.equals(generate));
    }
}
