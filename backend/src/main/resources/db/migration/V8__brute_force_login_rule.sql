-- The built-in brute-force login rule: five or more failed logins from one source address
-- within a minute.
--
-- Same contract as V1-V7: Flyway owns this DDL, Hibernate validates against it.
--
-- Seeded as data so it can be tuned or disabled like any other rule. The expression must stay
-- identical to BruteForceLoginRule.EXPRESSION, which documents what counts as a failed login;
-- FlywayMigrationTest checks that it does. A later change to the rule is a new migration,
-- because this one has already run wherever it was deployed.
INSERT INTO alert_rule (name, description, severity, expression)
VALUES (
    'brute-force-login',
    'Five or more failed logins from one source address within a minute: HTTP 401/403 on a'
        || ' login path, or sshd failed password.',
    'ERROR',
    '(status in (401, 403) and path matches "(?i)^[^?]*(log-?in|sign-?in|auth|session|token)")'
        || ' or (attributes.appName in ("sshd", "sshd-session")'
        || ' and message matches "^Failed (password|keyboard-interactive/pam) for ")'
        || ' | count by srcIp within 1m >= 5'
)
ON CONFLICT (name) DO NOTHING;
