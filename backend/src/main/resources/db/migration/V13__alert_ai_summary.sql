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
ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_summary CHECK (
    (ai_severity IS NULL AND ai_attack_type IS NULL AND ai_summary IS NULL
        AND ai_recommended_action IS NULL AND ai_model IS NULL AND ai_summarized_at IS NULL)
    OR (ai_severity IS NOT NULL AND ai_attack_type IS NOT NULL AND ai_summary IS NOT NULL
        AND ai_recommended_action IS NOT NULL AND ai_model IS NOT NULL
        AND ai_summarized_at IS NOT NULL)
);
