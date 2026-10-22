package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

public sealed interface Condition {

    boolean test(NormalizedEvent event);

    record Always() implements Condition {
        @Override
        public boolean test(NormalizedEvent event) {
            return true;
        }
    }

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

    record Exists(EventField field) implements Condition {
        public Exists {
            Objects.requireNonNull(field, "field");
        }

        @Override
        public boolean test(NormalizedEvent event) {
            return field.read(event) != null;
        }
    }

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
