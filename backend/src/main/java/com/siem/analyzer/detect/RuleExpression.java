package com.siem.analyzer.detect;

import java.util.Objects;

/**
 * A parsed rule: which events match, and optionally what to aggregate over them in time.
 *
 * @param condition the per-event test
 * @param window the aggregation; {@code null} for a rule that fires on every matching event
 */
public record RuleExpression(Condition condition, WindowSpec window) {

    public RuleExpression {
        Objects.requireNonNull(condition, "condition");
    }

    /** Whether the rule aggregates over a time window rather than firing per event. */
    public boolean isWindowed() {
        return window != null;
    }
}
