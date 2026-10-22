package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public record WindowSpec(
        Aggregation aggregation,
        List<EventField> groupBy,
        Duration window,
        Operator thresholdOperator,
        BigDecimal threshold) {

    public WindowSpec {
        Objects.requireNonNull(aggregation, "aggregation");
        groupBy = List.copyOf(groupBy);
        Objects.requireNonNull(window, "window");
        Objects.requireNonNull(thresholdOperator, "thresholdOperator");
        Objects.requireNonNull(threshold, "threshold");
        if (window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("window must be positive: " + window);
        }
        if (thresholdOperator != Operator.GT && thresholdOperator != Operator.GE) {
            throw new IllegalArgumentException(
                    "a window threshold must use > or >=, not " + thresholdOperator.symbol());
        }
        if (threshold.signum() < 0) {
            throw new IllegalArgumentException("threshold must not be negative: " + threshold);
        }
    }

    public boolean isMet(BigDecimal value) {
        return thresholdOperator.apply(value, threshold);
    }

    List<Object> groupKey(NormalizedEvent event) {
        if (groupBy.isEmpty()) {
            return List.of();
        }
        List<Object> key = new ArrayList<>(groupBy.size());
        for (EventField field : groupBy) {
            Object value = field.read(event);
            if (value == null) {
                return null;
            }
            key.add(value);
        }
        return Collections.unmodifiableList(key);
    }

    Map<String, Object> label(List<Object> key) {
        Map<String, Object> labelled = new LinkedHashMap<>();
        for (int i = 0; i < groupBy.size(); i++) {
            labelled.put(groupBy.get(i).name(), key.get(i));
        }
        return Collections.unmodifiableMap(labelled);
    }
}
