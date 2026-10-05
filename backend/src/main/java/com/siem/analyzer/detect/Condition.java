package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A test applied to one event — the part of a rule before the {@code |}.
 *
 * <p>Conditions are immutable and hold no state, so one instance may be tested from any number of
 * threads. Comparison semantics are those of {@link Operator}.
 */
public sealed interface Condition {

    boolean test(NormalizedEvent event);

    /** Matches every event: {@code true}, for rules that only count. */
    record Always() implements Condition {
        @Override
        public boolean test(NormalizedEvent event) {
            return true;
        }
    }

    /** {@code field <op> literal}, the literal being a {@link String} or a number. */
    record Compare(EventField field, Operator operator, Object operand) implements Condition {
        public Compare {
            Objects.requireNonNull(field, "field");
            Objects.requireNonNull(operator, "operator");
            Objects.requireNonNull(operand, "operand");
        }

        @Override
        public boolean test(NormalizedEvent event) {
            return operator.apply(field.read(event), operand);
        }
    }

    /** {@code field in (a, b, …)}: equal, in the sense of {@link Operator#EQ}, to any literal. */
    record In(EventField field, List<Object> operands) implements Condition {
        public In {
            Objects.requireNonNull(field, "field");
            operands = List.copyOf(operands);
        }

        @Override
        public boolean test(NormalizedEvent event) {
            Object actual = field.read(event);
            if (actual == null) {
                return false;
            }
            for (Object operand : operands) {
                if (Operator.looselyEqual(actual, operand)) {
                    return true;
                }
            }
            return false;
        }
    }

    /** {@code field exists}: the event carries a value for the field. */
    record Exists(EventField field) implements Condition {
        public Exists {
            Objects.requireNonNull(field, "field");
        }

        @Override
        public boolean test(NormalizedEvent event) {
            return field.read(event) != null;
        }
    }

    /**
     * {@code field matches "regex"}: the pattern is found anywhere in the value, as grep would.
     *
     * <p>Anchor with {@code ^…$} for a whole-value match; prefix {@code (?i)} to ignore case.
     */
    record Matches(EventField field, Pattern pattern) implements Condition {
        public Matches {
            Objects.requireNonNull(field, "field");
            Objects.requireNonNull(pattern, "pattern");
        }

        @Override
        public boolean test(NormalizedEvent event) {
            Object actual = field.read(event);
            return actual != null && pattern.matcher(String.valueOf(actual)).find();
        }
    }

    record And(List<Condition> operands) implements Condition {
        public And {
            operands = List.copyOf(operands);
        }

        @Override
        public boolean test(NormalizedEvent event) {
            for (Condition operand : operands) {
                if (!operand.test(event)) {
                    return false;
                }
            }
            return true;
        }
    }

    record Or(List<Condition> operands) implements Condition {
        public Or {
            operands = List.copyOf(operands);
        }

        @Override
        public boolean test(NormalizedEvent event) {
            for (Condition operand : operands) {
                if (operand.test(event)) {
                    return true;
                }
            }
            return false;
        }
    }

    record Not(Condition operand) implements Condition {
        public Not {
            Objects.requireNonNull(operand, "operand");
        }

        @Override
        public boolean test(NormalizedEvent event) {
            return !operand.test(event);
        }
    }
}
