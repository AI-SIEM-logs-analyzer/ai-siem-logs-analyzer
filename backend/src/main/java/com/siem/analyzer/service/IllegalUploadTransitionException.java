package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogUploadStatus;

/**
 * A log upload was asked to move to a status it cannot reach from the one it holds.
 *
 * <p>Ingestion messages can be redelivered, and two workers can pick up the same file, so a worker
 * that finishes twice or starts an already-finished batch is an expected event rather than a
 * programming error. Refusing the second move is what keeps {@code processed_at} and {@code
 * event_count} describing the run that actually produced them.
 */
public class IllegalUploadTransitionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient LogUploadStatus from;
    private final transient LogUploadStatus to;

    public IllegalUploadTransitionException(
            Long uploadId, LogUploadStatus from, LogUploadStatus to) {
        super("log upload " + uploadId + " cannot move from " + from + " to " + to);
        this.from = from;
        this.to = to;
    }

    public LogUploadStatus getFrom() {
        return from;
    }

    public LogUploadStatus getTo() {
        return to;
    }
}
