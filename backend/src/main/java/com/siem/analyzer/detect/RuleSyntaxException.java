package com.siem.analyzer.detect;

public final class RuleSyntaxException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    private final int position;

    RuleSyntaxException(String message, int position) {
        super(message + " (at position " + position + ")");
        this.position = position;
    }

    public int position() {
        return position;
    }
}
