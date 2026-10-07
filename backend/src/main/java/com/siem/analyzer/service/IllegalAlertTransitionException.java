package com.siem.analyzer.service;

import com.siem.analyzer.domain.AlertStatus;

/**
 * An alert was asked to move to a status it cannot reach from the one it holds.
 *
 * <p>Two analysts can work the same queue, so closing an alert someone else already closed is an
 * expected event rather than a programming error. Refusing the second move keeps {@code
 * resolved_at} describing the decision that actually closed it, and tells the second analyst so.
 */
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
