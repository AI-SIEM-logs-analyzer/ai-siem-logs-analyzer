ALTER TABLE alert ADD COLUMN ai_evidence JSONB;

ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_evidence CHECK (
    ai_evidence IS NULL
    OR (ai_summarized_at IS NOT NULL AND jsonb_typeof(ai_evidence) = 'array')
);
