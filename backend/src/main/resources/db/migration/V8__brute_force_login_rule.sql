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
