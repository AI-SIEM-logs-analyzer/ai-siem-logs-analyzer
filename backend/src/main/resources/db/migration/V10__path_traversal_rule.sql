-- The built-in path traversal rule: a request whose decoded path or query string climbs out of
-- its directory (../, ..\, /..;/, ....//) or names a system file (/etc/passwd, /proc/self/,
-- win.ini, ...), or whose raw path hides a dot or a slash in an overlong UTF-8 sequence (%c0%af).
--
-- Same contract as V1-V9: Flyway owns this DDL, Hibernate validates against it.
--
-- Seeded as data so it can be tuned or disabled like any other rule. The expression must stay
-- identical to PathTraversalRule.EXPRESSION, which documents each pattern; FlywayMigrationTest
-- checks that it does. A backslash inside the regex is written \x5c, so the literal needs no
-- escaping, and every slash, [/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}], also accepts the
-- fullwidth and division-slash look-alikes. A later change to the rule is a new migration,
-- because this one has already run wherever it was deployed.
INSERT INTO alert_rule (name, description, severity, expression)
VALUES (
    'path-traversal',
    'Path traversal attempt in the request: a parent segment such as ../ or ..\ (also encoded,'
        || ' double-encoded or overlong), a NUL byte, or a system file such as /etc/passwd,'
        || ' /proc/self/ or win.ini in the decoded path or query string.',
    'ERROR',
    'decodedPath matches "(?i)[.\x{FF0E}]{2}[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]'
        || '|(?:^|[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]|=)[.\x{FF0E}]{2}(?:$|[;?#&])'
        || '|%u(?:002e|002f|005c|ff0e|ff0f|ff3c|2215|2216)'
        || '|\x00'
        || '|\betc[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]++'
        || '(?:passwd|shadow|group|gshadow|sudoers|hosts|issue|crontab)\b'
        || '|\bproc[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]++'
        || '(?:self[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]'
        || '|\d++[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]++(?:environ|cmdline|maps|mem)\b)'
        || '|\.(?:ssh[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]|bash_history\b|htpasswd\b)'
        || '|\b(?:boot|win|system)\.ini\b'
        || '|\bwindows[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]++system32'
        || '[/\x5c\x{FF0F}\x{FF3C}\x{2215}\x{2216}]"'
        || ' or path matches "(?i)%(?:25)*+(?:c[01]|e0%(?:25)*+[89][0-9a-f]'
        || '|f0%(?:25)*+8[0-9a-f]%(?:25)*+[89ab][0-9a-f])%(?:25)*+[89ab][0-9a-f]"'
)
ON CONFLICT (name) DO NOTHING;
