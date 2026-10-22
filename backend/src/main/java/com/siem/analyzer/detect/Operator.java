package com.siem.analyzer.detect;

import java.math.BigDecimal;
import java.util.Locale;

public enum Operator {
    EQ("=="),
    NE("!="),
    GT(">"),
    GE(">="),
    LT("<"),
    LE("<="),
    CONTAINS("contains"),
    STARTS_WITH("startswith"),
    ENDS_WITH("endswith");

    private final String symbol;

    Operator(String symbol) {
        this.symbol = symbol;
    }

    public String symbol() {
        return symbol;
    }

    public boolean isOrdering() {
        return this == GT || this == GE || this == LT || this == LE;
    }

    public boolean apply(Object actual, Object operand) {
        if (actual == null) {
            return false;
        }
        return switch (this) {
            case EQ -> looselyEqual(actual, operand);
            case NE -> !looselyEqual(actual, operand);
            case GT, GE, LT, LE -> {
                BigDecimal left = toDecimal(actual);
                BigDecimal right = toDecimal(operand);
                if (left == null || right == null) {
                    yield false;
                }
                int order = left.compareTo(right);
                yield switch (this) {
                    case GT -> order > 0;
                    case GE -> order >= 0;
                    case LT -> order < 0;
                    default -> order <= 0;
                };
            }
            case CONTAINS -> lower(actual).contains(lower(operand));
            case STARTS_WITH -> lower(actual).startsWith(lower(operand));
            case ENDS_WITH -> lower(actual).endsWith(lower(operand));
        };
    }

    static boolean looselyEqual(Object actual, Object operand) {
        if (operand instanceof Number) {
            BigDecimal left = toDecimal(actual);
            return left != null && left.compareTo(toDecimal(operand)) == 0;
        }
        return String.valueOf(actual).equalsIgnoreCase(String.valueOf(operand));
    }

    static BigDecimal toDecimal(Object value) {
        if (value instanceof BigDecimal decimal) {
            return decimal;
        }
        if (value instanceof Integer || value instanceof Long || value instanceof Short) {
            return BigDecimal.valueOf(((Number) value).longValue());
        }
        if (value instanceof Number number) {
            double asDouble = number.doubleValue();
            return Double.isFinite(asDouble) ? new BigDecimal(number.toString()) : null;
        }
        if (value instanceof String text) {
            try {
                return new BigDecimal(text.strip());
            } catch (NumberFormatException notANumber) {
                return null;
            }
        }
        return null;
    }

    private static String lower(Object value) {
        return String.valueOf(value).toLowerCase(Locale.ROOT);
    }
}
