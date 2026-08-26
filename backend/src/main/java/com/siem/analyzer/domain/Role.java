package com.siem.analyzer.domain;

/**
 * What a {@link User} is allowed to do.
 *
 * <p>The three levels are cumulative in practice — an administrator can do everything an analyst
 * can — but they are not modelled as a hierarchy, because a user holds a set of roles and the check
 * that matters is always "does this set contain the role this operation needs".
 *
 * <p>Constant names are the stored values, listed by the {@code ck_user_role} constraint.
 */
public enum Role {

    /** Manages accounts, log sources and detection rules. */
    ADMIN,

    /** Triages alerts and edits detection rules; cannot manage accounts. */
    ANALYST,

    /** Read-only access to events, alerts and dashboards. */
    VIEWER
}
