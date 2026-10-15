-- MITRE ATT&CK Enterprise as reference data, and which techniques each detection rule evidences.
--
-- Same contract as V1-V14: Flyway owns this DDL, Hibernate validates against it.
--
-- The four attack_* tables hold the dataset attack.AttackDatasetService imports from the official
-- STIX bundle. An import replaces them wholesale, so nothing outside them may point into them
-- with a foreign key. alert_rule_technique is the one table that names techniques, and it does so
-- by value: the seed below runs before any dataset exists, and a later ATT&CK release that
-- retires a technique must not be able to break a rule. An ID the dataset does not know is shown
-- bare, without a name or a link.

CREATE TABLE attack_tactic (
    id        TEXT    PRIMARY KEY,
    name      TEXT    NOT NULL,
    -- The tactic's handle in kill_chain_phases (credential-access), which is how a technique
    -- names its tactics in STIX.
    shortname TEXT    NOT NULL,
    url       TEXT,
    -- Position in the Enterprise matrix, left to right, so a listing reads like the matrix.
    ordinal   INTEGER NOT NULL,

    CONSTRAINT uq_attack_tactic_shortname UNIQUE (shortname),
    CONSTRAINT ck_attack_tactic_id CHECK (id ~ '^TA[0-9]{4}$')
);

CREATE TABLE attack_technique (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    -- The base technique of a sub-technique (T1110 for T1110.001); NULL on a base technique.
    -- No foreign key: the importer writes techniques in ID order, not parents first, and a
    -- sub-technique's parent is always in the same bundle anyway.
    parent_id TEXT,
    url       TEXT,

    CONSTRAINT ck_attack_technique_id CHECK (id ~ '^T[0-9]{4}(\.[0-9]{3})?$')
);

-- A technique can sit under several tactics (Valid Accounts is initial access, persistence,
-- privilege escalation and defense evasion at once).
CREATE TABLE attack_technique_tactic (
    technique_id TEXT NOT NULL REFERENCES attack_technique (id) ON DELETE CASCADE,
    tactic_id    TEXT NOT NULL REFERENCES attack_tactic (id) ON DELETE CASCADE,

    PRIMARY KEY (technique_id, tactic_id)
);

-- The tactic filter on the alert list goes from a tactic to its techniques.
CREATE INDEX ix_attack_technique_tactic_tactic ON attack_technique_tactic (tactic_id);

-- Which release is loaded. One row at most: the tables hold one dataset at a time.
CREATE TABLE attack_dataset (
    id              SMALLINT    PRIMARY KEY,
    version         TEXT        NOT NULL,
    -- SHA-256 of the bundle's JSON, so two deployments can tell they hold the same file.
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

-- The technique filter on the alert list goes from a technique to the rules that map it.
CREATE INDEX ix_alert_rule_technique_technique ON alert_rule_technique (technique_id);

-- The built-in rules (V8-V11), joined by name so a deployment that renamed or deleted one simply
-- gets no row for it.
--
--   brute-force-login   counts failed logins per source address: one address guessing one
--                       account's password, or one password across many accounts
--   sql-injection       an injection payload in the request to a web application
--   path-traversal      climbing out of the web root to read files on the server
--   scanner-user-agent  vulnerability scanners (sqlmap, Nikto, Nuclei) and wordlist scanners
--                       (gobuster, ffuf, dirb) named in the User-Agent
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
