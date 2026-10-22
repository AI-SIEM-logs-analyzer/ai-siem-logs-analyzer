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
