CREATE TABLE attack_tactic (
    id        TEXT    PRIMARY KEY,
    name      TEXT    NOT NULL,
    shortname TEXT    NOT NULL,
    url       TEXT,
    ordinal   INTEGER NOT NULL,

    CONSTRAINT uq_attack_tactic_shortname UNIQUE (shortname),
    CONSTRAINT ck_attack_tactic_id CHECK (id ~ '^TA[0-9]{4}$')
);

CREATE TABLE attack_technique (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    parent_id TEXT,
    url       TEXT,

    CONSTRAINT ck_attack_technique_id CHECK (id ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

CREATE TABLE attack_technique_tactic (
    technique_id TEXT NOT NULL REFERENCES attack_technique (id) ON DELETE CASCADE,
    tactic_id    TEXT NOT NULL REFERENCES attack_tactic (id) ON DELETE CASCADE,

    PRIMARY KEY (technique_id, tactic_id)
);

CREATE INDEX ix_attack_technique_tactic_tactic ON attack_technique_tactic (tactic_id);

CREATE TABLE attack_dataset (
    id              SMALLINT    PRIMARY KEY,
    version         TEXT        NOT NULL,
    sha256          TEXT        NOT NULL,
    technique_count INTEGER     NOT NULL,
    imported_at     TIMESTAMPTZ NOT NULL,

    CONSTRAINT ck_attack_dataset_single_row CHECK (id = 1)
);

CREATE TABLE alert_rule_technique (
    rule_id      BIGINT NOT NULL REFERENCES alert_rule (id) ON DELETE CASCADE,
    technique_id TEXT   NOT NULL,

    PRIMARY KEY (rule_id, technique_id),
    CONSTRAINT ck_alert_rule_technique_id CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

CREATE INDEX ix_alert_rule_technique_technique ON alert_rule_technique (technique_id);

INSERT INTO alert_rule_technique (rule_id, technique_id)
SELECT r.id, m.technique_id
FROM alert_rule r
JOIN (VALUES
    ('brute-force-login',  'T1110.001'),
    ('brute-force-login',  'T1110.003'),
    ('sql-injection',      'T1190'),
    ('path-traversal',     'T1190'),
    ('path-traversal',     'T1083'),
    ('scanner-user-agent', 'T1595.002'),
    ('scanner-user-agent', 'T1595.003')
) AS m (rule_name, technique_id) ON m.rule_name = r.name
ON CONFLICT DO NOTHING;
