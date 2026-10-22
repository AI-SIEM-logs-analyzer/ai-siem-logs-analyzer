package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.Objects;

public sealed interface Aggregation {

    Object contribution(NormalizedEvent event);

    String describe();

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
