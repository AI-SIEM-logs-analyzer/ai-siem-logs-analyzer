package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;

public final class BruteForceLoginRule {

    public static final String NAME = "brute-force-login";

    public static final Severity SEVERITY = Severity.ERROR;

    public static final int THRESHOLD = 5;

    public static final String EXPRESSION =
            "(status in (401, 403)"
                    + " and path matches \"(?i)^[^?]*(log-?in|sign-?in|auth|session|token)\")"
                    + " or (attributes.appName in (\"sshd\", \"sshd-session\")"
                    + " and message matches \"^Failed (password|keyboard-interactive/pam) for \")"
                    + " | count by srcIp within 1m >= "
                    + THRESHOLD;

    private BruteForceLoginRule() {}

    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
