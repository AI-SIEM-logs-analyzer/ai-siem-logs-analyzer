package com.siem.analyzer.service;

/** An upload larger than the configured limit; carries the limit so the caller can be told it. */
public class PayloadTooLargeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long maxSizeBytes;

    public PayloadTooLargeException(long actualSizeBytes, long maxSizeBytes) {
        super("uploaded file is " + actualSizeBytes + " bytes, limit is " + maxSizeBytes);
        this.maxSizeBytes = maxSizeBytes;
    }

    public long getMaxSizeBytes() {
        return maxSizeBytes;
    }
}
