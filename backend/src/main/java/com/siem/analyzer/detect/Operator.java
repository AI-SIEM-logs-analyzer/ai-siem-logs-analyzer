package com.siem.analyzer.detect;

import java.math.BigDecimal;
import java.util.Locale;

/**
 * How a predicate compares a field's value with the literal in the rule.
 *
 * <p>The semantics are chosen so a rule author never has to know how a parser typed a value:
 *
 * <ul>
 *   <li>Against a number literal, the field is compared as a number, so {@code status == 401}
 *       matches both the integer an access log yields and the string {@code "401"} a JSON log may
 *       carry. A value that is not a number matches nothing.
 *   <li>Against a string literal, the field is compared as text, ignoring case: {@code severity ==
 *       "error"} and {@code path startswith "/ADMIN"} do what an analyst means.
 *   <li>The ordering operators ({@code > >= < <=}) are numeric only.
 *   <li>An absent field ({@code null}) fails every comparison, {@code !=} included. A rule that
 *       wants "absent or different" says so: {@code not user exists or user != "root"}.
 * </ul>
 */
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

    /** How the operator is written in a rule expression. */
    public String symbol() {
        return symbol;
    }

    /** Whether the operator orders numbers, and so only accepts a number literal. */
    public boolean isOrdering() {
        return this == GT || this == GE || this == LT || this == LE;
    }

    /** Applies the operator to a field value and a rule literal ({@link String} or number). */
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

    /**
     * Reads a value as an exact decimal, or {@code null} when it is not a number.
     *
     * <p>Strings are accepted because JSON logs and attributes often quote their numbers. Going
     * through {@link BigDecimal} rather than {@code double} keeps {@code bytes} sums exact and lets
     * a window subtract what it added without drifting.
     */
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
