package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;

/**
 * The built-in brute-force login rule: five or more failed logins from one source address within a
 * minute.
 *
 * <p>A failed login is either
 *
 * <ul>
 *   <li>an HTTP request to a login-like path ({@code /login}, {@code /signin}, {@code /auth},
 *       {@code /session}, {@code /token}, {@code wp-login.php}, …) answered 401 or 403, or
 *   <li>an sshd {@code Failed password} or {@code Failed keyboard-interactive/pam} line, whose
 *       address {@link com.siem.analyzer.parse.SyslogParser} reads out of the message.
 * </ul>
 *
 * <p>sshd also writes {@code Invalid user …} for an unknown account, but always together with the
 * {@code Failed password for invalid user …} line of the same attempt, so only the latter counts. A
 * failed public key is not counted: clients offer every key they hold, so one legitimate login can
 * log several. A run that rsyslog folds into {@code message repeated N times} counts once.
 *
 * <p>Flyway migration {@code V8__brute_force_login_rule.sql} stores this rule in {@code alert_rule}
 * under {@link #NAME}, where it can be tuned or disabled; this class is the reference for that row
 * and for running the rule without a database.
 */
public final class BruteForceLoginRule {

    /** The rule's name in {@code alert_rule}. */
    public static final String NAME = "brute-force-login";

    public static final Severity SEVERITY = Severity.ERROR;

    /** Failed attempts from one address that make a brute force. */
    public static final int THRESHOLD = 5;

    public static final String EXPRESSION =
            "(status in (401, 403)"
                    + " and path matches \"(?i)^[^?]*(log-?in|sign-?in|auth|session|token)\")"
                    + " or (attributes.appName in (\"sshd\", \"sshd-session\")"
                    + " and message matches \"^Failed (password|keyboard-interactive/pam) for \")"
                    + " | count by srcIp within 1m >= "
                    + THRESHOLD;

    private BruteForceLoginRule() {}

    /** The rule ready for a {@link RuleEngine}, with no stored row behind it. */
    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
