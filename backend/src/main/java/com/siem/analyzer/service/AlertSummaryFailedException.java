package com.siem.analyzer.service;

public class AlertSummaryFailedException extends RuntimeException {

    private final Long alertId;
    private final boolean ungrounded;

    public AlertSummaryFailedException(Long alertId, Throwable cause) {
        super("could not summarise alert " + alertId, cause);
        this.alertId = alertId;
        this.ungrounded = false;
    }

    public AlertSummaryFailedException(Long alertId, String reason) {
        this(alertId, reason, false);
    }

    private AlertSummaryFailedException(Long alertId, String reason, boolean ungrounded) {
        super("could not summarise alert " + alertId + ": " + reason);
        this.alertId = alertId;
        this.ungrounded = ungrounded;
    }

    public static AlertSummaryFailedException ungrounded(Long alertId) {
        return new AlertSummaryFailedException(
                alertId, "the model's answer cites values the alert does not contain", true);
    }

    public Long getAlertId() {
        return alertId;
    }

    public boolean isUngrounded() {
        return ungrounded;
    }
}
