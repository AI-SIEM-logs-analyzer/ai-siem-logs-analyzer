package com.siem.analyzer.detect.sigma;

public final class SigmaException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    public SigmaException(String message) {
        super(message);
    }
}
