package com.siem.analyzer.service;

/**
 * The AI provider gave no usable summary of an alert: it could not be reached, refused, timed out,
 * or answered with something that does not parse into a complete summary.
 *
 * <p>The alert is left as it was, its previous summary included.
 */
public class AlertSummaryFailedException extends RuntimeException {

    private final Long alertId;

    public AlertSummaryFailedException(Long alertId, Throwable cause) {
        super("could not summarise alert " + alertId, cause);
        this.alertId = alertId;
    }

    public AlertSummaryFailedException(Long alertId, String reason) {
        super("could not summarise alert " + alertId + ": " + reason);
        this.alertId = alertId;
    }

    public Long getAlertId() {
        return alertId;
    }
}
