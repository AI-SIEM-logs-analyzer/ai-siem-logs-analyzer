package com.siem.analyzer.service;

import java.time.Duration;

/** Too many failed sign-ins for this username and address; carries how long to wait. */
public class RateLimitedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient Duration retryAfter;

    public RateLimitedException(Duration retryAfter) {
        super("too many sign-in attempts");
        this.retryAfter = retryAfter;
    }

    public Duration getRetryAfter() {
        return retryAfter;
    }
}
