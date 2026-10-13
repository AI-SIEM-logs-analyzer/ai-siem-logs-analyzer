-- A model's summary of an alert: the structured answer of ai.AlertSummarizer.
--
-- Same contract as V1-V12: Flyway owns this DDL, Hibernate validates against it.
--
-- Kept beside the alert rather than in a table of its own: an alert has one current summary, a new
-- one replaces it, and the alerts page reads it with every row. The model's severity is its own
-- column and never overwrites alert.severity, which stays what the rule said.
--   ai_severity            how serious the model judged the alert
--   ai_attack_type         what kind of attack it judged it to be (domain.AttackType)
--   ai_summary             a few sentences for the analyst
--   ai_recommended_action  the next step it proposes
--   ai_model               which model answered, as provider/model
--   ai_summarized_at       when it answered
ALTER TABLE alert ADD COLUMN ai_severity           TEXT;
ALTER TABLE alert ADD COLUMN ai_attack_type        TEXT;
ALTER TABLE alert ADD COLUMN ai_summary            TEXT;
ALTER TABLE alert ADD COLUMN ai_recommended_action TEXT;
ALTER TABLE alert ADD COLUMN ai_model              TEXT;
ALTER TABLE alert ADD COLUMN ai_summarized_at      TIMESTAMPTZ;

ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_severity CHECK (
    ai_severity IS NULL OR ai_severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
);
ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_attack_type CHECK (
    ai_attack_type IS NULL OR ai_attack_type IN (
        'BRUTE_FORCE', 'CREDENTIAL_STUFFING', 'SQL_INJECTION', 'PATH_TRAVERSAL',
        'CROSS_SITE_SCRIPTING', 'COMMAND_INJECTION', 'REMOTE_CODE_EXECUTION', 'RECONNAISSANCE',
        'DENIAL_OF_SERVICE', 'PRIVILEGE_ESCALATION', 'DATA_EXFILTRATION', 'MALWARE',
        'ANOMALOUS_BEHAVIOUR', 'BENIGN', 'OTHER'
    )
);
-- A summary is all six columns or none of them: half a summary is one nobody can trust.
ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_summary CHECK (
    (ai_severity IS NULL AND ai_attack_type IS NULL AND ai_summary IS NULL
        AND ai_recommended_action IS NULL AND ai_model IS NULL AND ai_summarized_at IS NULL)
    OR (ai_severity IS NOT NULL AND ai_attack_type IS NOT NULL AND ai_summary IS NOT NULL
        AND ai_recommended_action IS NOT NULL AND ai_model IS NOT NULL
        AND ai_summarized_at IS NOT NULL)
);
