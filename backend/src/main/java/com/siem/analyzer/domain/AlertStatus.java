package com.siem.analyzer.domain;

public enum AlertStatus {
    NEW,

    IN_PROGRESS,

    RESOLVED,

    FALSE_POSITIVE;

    public boolean isClosed() {
        return this == RESOLVED || this == FALSE_POSITIVE;
    }

    public boolean canMoveTo(AlertStatus target) {
        return switch (this) {
            case NEW -> target == IN_PROGRESS || target.isClosed();
            case IN_PROGRESS -> target == NEW || target.isClosed();
            case RESOLVED, FALSE_POSITIVE -> target == IN_PROGRESS;
        };
    }
}
