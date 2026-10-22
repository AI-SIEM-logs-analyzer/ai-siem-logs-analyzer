package com.siem.analyzer.service;

import java.time.Duration;

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
