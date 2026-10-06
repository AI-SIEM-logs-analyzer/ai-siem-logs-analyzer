package com.siem.analyzer.detect.sigma;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * One Sigma correlation rule (Sigma 2): a count over the events other rules match, per group,
 * within a time span.
 *
 * <pre>
 * correlation:
 *   type: event_count
 *   rules: [failed_login]
 *   group-by: [c-ip]
 *   timespan: 5m
 *   condition: {gte: 10}
 * </pre>
 *
 * @param meta title, identity and the other descriptive keys
 * @param type {@code event_count}, {@code value_count}, {@code value_sum}, {@code temporal}, …, as
 *     written
 * @param rules the {@code name}s or {@code id}s of the rules whose events are counted
 * @param groupBy Sigma field names; empty for one count over every event
 * @param timespan as written, {@code 5m}
 * @param thresholdOperator the condition's key: {@code gt}, {@code gte}, {@code lt}, …
 * @param threshold the condition's value
 * @param field the field {@code value_count} and {@code value_sum} read; {@code null} otherwise
 * @param generate whether the referenced rules also stand on their own
 */
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

    /**
     * Reads a correlation document.
     *
     * @throws SigmaException a required key is missing or has the wrong shape
     */
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
