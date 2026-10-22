package com.siem.analyzer.service;

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
