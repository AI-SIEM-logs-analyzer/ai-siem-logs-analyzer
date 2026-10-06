package com.siem.analyzer.detect.sigma;

import java.util.ArrayList;
import java.util.List;

/**
 * A Sigma string value: literal text interleaved with the wildcards {@code *} (any run of
 * characters) and {@code ?} (any one character).
 *
 * <p>A backslash escapes a wildcard or another backslash ({@code \*}, {@code \?}, {@code \\});
 * before anything else it is a literal backslash, so a Windows path needs no doubling. Instances
 * are immutable; adjacent literals are merged and runs of {@code *} collapse into one.
 */
final class SigmaString {

    private sealed interface Part {}

    private record Text(String value) implements Part {}

    private enum Wildcard implements Part {
        ANY,
        ONE
    }

    private final List<Part> parts;

    private SigmaString(List<Part> parts) {
        List<Part> normalized = new ArrayList<>(parts.size());
        for (Part part : parts) {
            Part previous = normalized.isEmpty() ? null : normalized.get(normalized.size() - 1);
            if (part instanceof Text text && text.value().isEmpty()) {
                continue;
            }
            if (part instanceof Text text && previous instanceof Text before) {
                normalized.set(normalized.size() - 1, new Text(before.value() + text.value()));
            } else if (part == Wildcard.ANY && previous == Wildcard.ANY) {
                continue;
            } else {
                normalized.add(part);
            }
        }
        this.parts = List.copyOf(normalized);
    }

    /** Reads a value as Sigma writes it, wildcards and escapes included. */
    static SigmaString parse(String value) {
        List<Part> parts = new ArrayList<>();
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && i + 1 < value.length() && "*?\\".indexOf(value.charAt(i + 1)) >= 0) {
                text.append(value.charAt(++i));
            } else if (c == '*' || c == '?') {
                parts.add(new Text(text.toString()));
                text.setLength(0);
                parts.add(c == '*' ? Wildcard.ANY : Wildcard.ONE);
            } else {
                text.append(c);
            }
        }
        parts.add(new Text(text.toString()));
        return new SigmaString(parts);
    }

    /** Plain text, with no wildcards in it whatever characters it holds. */
    static SigmaString literal(String value) {
        return new SigmaString(List.of(new Text(value)));
    }

    /** This value with the implicit wildcards a match modifier adds. */
    SigmaString anchoredFor(SigmaConverter.Match match) {
        List<Part> anchored = new ArrayList<>(parts.size() + 2);
        if (match == SigmaConverter.Match.CONTAINS || match == SigmaConverter.Match.ENDS_WITH) {
            anchored.add(Wildcard.ANY);
        }
        anchored.addAll(parts);
        if (match == SigmaConverter.Match.CONTAINS || match == SigmaConverter.Match.STARTS_WITH) {
            anchored.add(Wildcard.ANY);
        }
        return new SigmaString(anchored);
    }

    boolean startsWithAny() {
        return !parts.isEmpty() && parts.get(0) == Wildcard.ANY;
    }

    boolean endsWithAny() {
        return !parts.isEmpty() && parts.get(parts.size() - 1) == Wildcard.ANY;
    }

    /** This value without a leading or trailing {@code *}. */
    SigmaString trimAny() {
        int from = startsWithAny() ? 1 : 0;
        int to = endsWithAny() && parts.size() > from ? parts.size() - 1 : parts.size();
        return new SigmaString(parts.subList(from, to));
    }

    boolean isEmpty() {
        return parts.isEmpty();
    }

    /** Whether the value holds no wildcard, so {@link #literal()} is all of it. */
    boolean isLiteral() {
        return parts.stream().allMatch(Text.class::isInstance);
    }

    /** The text of a value that {@link #isLiteral() is literal}; empty for an empty value. */
    String literal() {
        StringBuilder text = new StringBuilder();
        for (Part part : parts) {
            if (!(part instanceof Text literal)) {
                throw new IllegalStateException("not a literal: " + this);
            }
            text.append(literal.value());
        }
        return text.toString();
    }

    /** An unanchored regular expression: literals escaped, {@code *} and {@code ?} as dots. */
    String toRegex() {
        StringBuilder regex = new StringBuilder();
        for (Part part : parts) {
            switch (part) {
                case Text text -> regex.append(SigmaConverter.regexLiteral(text.value()));
                case Wildcard wildcard -> regex.append(wildcard == Wildcard.ANY ? ".*" : ".");
            }
        }
        return regex.toString();
    }

    @Override
    public String toString() {
        StringBuilder value = new StringBuilder();
        for (Part part : parts) {
            switch (part) {
                case Text text ->
                        value.append(
                                text.value()
                                        .replace("\\", "\\\\")
                                        .replace("*", "\\*")
                                        .replace("?", "\\?"));
                case Wildcard wildcard -> value.append(wildcard == Wildcard.ANY ? '*' : '?');
            }
        }
        return value.toString();
    }
}
