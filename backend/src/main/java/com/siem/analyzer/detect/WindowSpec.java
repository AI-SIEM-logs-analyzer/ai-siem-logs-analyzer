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

/**
 * The part of a rule after the {@code |}: aggregate the matching events per group over a sliding
 * window, and fire when the aggregate crosses a threshold.
 *
 * <p>Only {@code >} and {@code >=} thresholds exist. The engine is driven by events, so it only
 * ever looks at a window when an event arrives; "fewer than N in five minutes" would need a timer
 * to notice the window closing with nothing in it, and would fire on the first event of every group
 * besides.
 *
 * @param aggregation what is measured
 * @param groupBy the fields that split the stream into independent windows; empty for one window
 *     over every matching event
 * @param window how far back from the newest event in a group the window reaches; positive
 * @param thresholdOperator {@link Operator#GT} or {@link Operator#GE}
 * @param threshold the value the aggregate is compared with; not negative
 */
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

    /** Whether an aggregate value crosses the threshold. */
    public boolean isMet(BigDecimal value) {
        return thresholdOperator.apply(value, threshold);
    }

    /**
     * The group an event belongs to, or {@code null} when it lacks one of the group-by fields.
     *
     * <p>Events without a key are skipped rather than pooled: lumping every line with no {@code
     * srcIp} into one group would let unrelated sources add up to an alert about nobody.
     */
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

    /** A group key labelled with its field names, in group-by order. */
    Map<String, Object> label(List<Object> key) {
        Map<String, Object> labelled = new LinkedHashMap<>();
        for (int i = 0; i < groupBy.size(); i++) {
            labelled.put(groupBy.get(i).name(), key.get(i));
        }
        return Collections.unmodifiableMap(labelled);
    }
}
