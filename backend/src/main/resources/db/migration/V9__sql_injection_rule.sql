-- The built-in SQL injection rule: a request whose decoded path or query string carries a SQL
-- injection pattern (' OR 1=1, UNION SELECT, admin'--, ; DROP TABLE, SLEEP(5), ...).
--
-- Same contract as V1-V8: Flyway owns this DDL, Hibernate validates against it.
--
-- Seeded as data so it can be tuned or disabled like any other rule. The expression must stay
-- identical to SqlInjectionRule.EXPRESSION, which documents each pattern; FlywayMigrationTest
-- checks that it does. Quotes inside the regex are written \x22 and \x27, so the literal needs
-- no escaping, and every gap between SQL words, (?:\s|/\*[^*]*+\*/), accepts whitespace or an
-- inline comment. A later change to the rule is a new migration, because this one has already
-- run wherever it was deployed.
INSERT INTO alert_rule (name, description, severity, expression)
VALUES (
    'sql-injection',
    'SQL injection attempt in the request: a tautology such as '' OR 1=1, UNION SELECT, a'
        || ' quote followed by a comment, a stacked statement, a time delay or a catalogue name in'
        || ' the decoded path or query string.',
    'ERROR',
    'decodedPath matches "(?i)\bunion(?:(?:\s|/\*[^*]*+\*/)++(?:all|distinct))?(?:'
        || '(?:\s|/\*[^*]*+\*/)++|(?:\s|/\*[^*]*+\*/)*+\((?:\s|/\*[^*]*+\*/)*+)select\b'
        || '|[\x22\x27](?:\s|/\*[^*]*+\*/)*+\)?(?:\s|/\*[^*]*+\*/)*+(?:(?:or|and)\b|\|\||&&)'
        || '(?:\s|/\*[^*]*+\*/)*+\(?(?:\s|/\*[^*]*+\*/)*+[\x22\x27]?\w*+[\x22\x27]?'
        || '(?:\s|/\*[^*]*+\*/)*+(?:=|<>|!=|\blike\b)(?:\s|/\*[^*]*+\*/)*+[\x22\x27\w(]'
        || '|\b(?:or|and)(?:\s|/\*[^*]*+\*/)++\d++(?:\s|/\*[^*]*+\*/)*+(?:=|<>|!=)'
        || '(?:\s|/\*[^*]*+\*/)*+\d++\b'
        || '|[\x22\x27](?:\s|/\*[^*]*+\*/)*+\)?(?:\s|/\*[^*]*+\*/)*+(?:--|/\*|#(?=$|[\s&]))'
        || '|[\x22\x27](?:\s|/\*[^*]*+\*/)*+\)?(?:\s|/\*[^*]*+\*/)*+(?:order|group)'
        || '(?:\s|/\*[^*]*+\*/)++by\b'
        || '|;(?:\s|/\*[^*]*+\*/)*+'
        || '(?:drop|truncate|alter|create|delete|insert|update|exec(?:ute)?|declare)'
        || '(?:\s|/\*[^*]*+\*/)++\w'
        || '|\b(?:sleep|pg_sleep|benchmark)(?:\s|/\*[^*]*+\*/)*+\((?:\s|/\*[^*]*+\*/)*+\d'
        || '|\bwaitfor(?:\s|/\*[^*]*+\*/)++delay(?:\s|/\*[^*]*+\*/)++[\x22\x27]'
        || '|\b(?:and|or)(?:\s|/\*[^*]*+\*/)*+\((?:\s|/\*[^*]*+\*/)*+select\b'
        || '|\b(?:extractvalue|updatexml|load_file)(?:\s|/\*[^*]*+\*/)*+\('
        || '|\binto(?:\s|/\*[^*]*+\*/)++(?:out|dump)file\b'
        || '|\b(?:information_schema|sqlite_master|sysobjects|xp_cmdshell)\b'
        || '|@@version\b"'
)
ON CONFLICT (name) DO NOTHING;
