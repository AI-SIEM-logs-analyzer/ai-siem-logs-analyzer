package com.siem.analyzer.service;

import com.siem.analyzer.domain.AlertStatus;

public class IllegalAlertTransitionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient AlertStatus from;
    private final transient AlertStatus to;

    public IllegalAlertTransitionException(Long alertId, AlertStatus from, AlertStatus to) {
        super("alert " + alertId + " cannot move from " + from + " to " + to);
        this.from = from;
        this.to = to;
    }

    public AlertStatus getFrom() {
        return from;
    }

    public AlertStatus getTo() {
        return to;
    }
}
