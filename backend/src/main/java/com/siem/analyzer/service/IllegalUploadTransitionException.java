package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogUploadStatus;

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
