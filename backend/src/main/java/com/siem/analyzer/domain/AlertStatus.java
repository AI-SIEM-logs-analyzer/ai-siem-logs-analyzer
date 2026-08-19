package com.siem.analyzer.domain;

/**
 * Where an alert sits in triage.
 *
 * <p>{@code FALSE_POSITIVE} is a terminal state distinct from {@code RESOLVED}: the two mean
 * different things to an analyst, and telling them apart is what makes this column usable as a
 * label later on.
 *
 * <p>Constant names are the stored values, listed by the {@code ck_alert_status} constraint.
 */
public enum AlertStatus {
    OPEN,
    ACKNOWLEDGED,
    RESOLVED,
    FALSE_POSITIVE
}
