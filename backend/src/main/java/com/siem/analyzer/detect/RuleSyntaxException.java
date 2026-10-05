package com.siem.analyzer.detect;

/** A rule expression that does not parse; the message says what was expected, and where. */
public final class RuleSyntaxException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    private final int position;

    RuleSyntaxException(String message, int position) {
        super(message + " (at position " + position + ")");
        this.position = position;
    }

    /** Zero-based offset into the expression where the problem was found. */
    public int position() {
        return position;
    }
}
