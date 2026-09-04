package com.siem.analyzer.service;

import java.time.Duration;

/** This account has uploaded too often; carries how long it has to wait. */
public class UploadRateLimitedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient Duration retryAfter;

    public UploadRateLimitedException(Duration retryAfter) {
        super("too many uploads");
        this.retryAfter = retryAfter;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }
}
