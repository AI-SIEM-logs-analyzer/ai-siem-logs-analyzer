package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.Objects;

/** What a windowed rule measures over the events that fall inside its window. */
public sealed interface Aggregation {

    /**
     * What one event contributes, or {@code null} when it contributes nothing and the rule should
     * skip it — an event with no {@code user} cannot add to {@code distinct(user)}.
     */
    Object contribution(NormalizedEvent event);

    /** How the aggregation is written in a rule expression. */
    String describe();

    /** {@code count}: how many matching events the window holds. */
    record Count() implements Aggregation {
        @Override
        public Object contribution(NormalizedEvent event) {
            return Boolean.TRUE;
        }

        @Override
        public String describe() {
            return "count";
        }
    }

    /** {@code distinct(field)}: how many different values of the field the window holds. */
    record DistinctCount(EventField field) implements Aggregation {
        public DistinctCount {
            Objects.requireNonNull(field, "field");
        }

        @Override
        public Object contribution(NormalizedEvent event) {
            return field.read(event);
        }

        @Override
        public String describe() {
            return "distinct(" + field.name() + ")";
        }
    }

    /**
     * {@code sum(field)}: the total of a numeric field; values that are not numbers are skipped.
     */
    record Sum(EventField field) implements Aggregation {
        public Sum {
            Objects.requireNonNull(field, "field");
        }

        @Override
        public Object contribution(NormalizedEvent event) {
            return Operator.toDecimal(field.read(event));
        }

        @Override
        public String describe() {
            return "sum(" + field.name() + ")";
        }
    }
}
