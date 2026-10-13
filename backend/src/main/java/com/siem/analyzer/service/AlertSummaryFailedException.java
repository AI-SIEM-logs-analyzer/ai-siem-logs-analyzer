package com.siem.analyzer.service;

/**
 * The AI provider gave no usable summary of an alert: it could not be reached, refused, timed out,
 * answered with something that does not parse into a complete summary, or cited values the alert
 * does not contain.
 *
 * <p>The alert is left as it was, its previous summary included.
 */
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

    /** The model answered, but cited what the alert does not contain, so the answer was dropped. */
    public static AlertSummaryFailedException ungrounded(Long alertId) {
        return new AlertSummaryFailedException(
                alertId, "the model's answer cites values the alert does not contain", true);
    }

    public Long getAlertId() {
        return alertId;
    }

    /** Whether the answer was dropped for citing what the alert does not contain. */
    public boolean isUngrounded() {
        return ungrounded;
    }
}
