package com.siem.analyzer.domain;

/**
 * Where an alert sits in triage.
 *
 * <ul>
 *   <li>{@code NEW} → {@code IN_PROGRESS}, {@code RESOLVED}, {@code FALSE_POSITIVE}
 *   <li>{@code IN_PROGRESS} → {@code NEW}, {@code RESOLVED}, {@code FALSE_POSITIVE}
 *   <li>{@code RESOLVED}, {@code FALSE_POSITIVE} → {@code IN_PROGRESS}
 * </ul>
 *
 * <p>A new alert can be picked up or closed straight away; one being worked on can be closed or
 * handed back to the queue; a closed alert can only be reopened, and reopening puts it back in
 * someone's hands rather than at the bottom of the queue. Moving to the status an alert already
 * holds is not a transition: it changes nothing and is refused, so a second analyst closing the
 * same alert learns that someone else already did.
 *
 * <p>{@code FALSE_POSITIVE} is a closed state distinct from {@code RESOLVED}: the two mean
 * different things to an analyst, and telling them apart is what makes this column usable as a
 * label later on.
 *
 * <p>Constant names are the stored values, listed by the {@code ck_alert_status} constraint.
 */
public enum AlertStatus {

    /** Raised and waiting in the triage queue; nobody has looked at it yet. */
    NEW,

    /** An analyst is investigating. */
    IN_PROGRESS,

    /** Closed: a real finding, dealt with. */
    RESOLVED,

    /** Closed: the rule or model fired on something harmless. */
    FALSE_POSITIVE;

    /** Whether the alert is closed, which is when {@code resolved_at} is set. */
    public boolean isClosed() {
        return this == RESOLVED || this == FALSE_POSITIVE;
    }

    /** Whether an alert holding this status may move to {@code target}. */
    public boolean canMoveTo(AlertStatus target) {
        return switch (this) {
            case NEW -> target == IN_PROGRESS || target.isClosed();
            case IN_PROGRESS -> target == NEW || target.isClosed();
            case RESOLVED, FALSE_POSITIVE -> target == IN_PROGRESS;
        };
    }
}
