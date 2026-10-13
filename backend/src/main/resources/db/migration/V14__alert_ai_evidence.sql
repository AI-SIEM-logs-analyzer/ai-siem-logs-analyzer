-- The evidence a model's summary rests on: the values it copied from the alert, each one checked
-- by ai.Grounding to be in the alert before the summary was stored.
--
-- Same contract as V1-V13: Flyway owns this DDL, Hibernate validates against it.
--
--   ai_evidence  a JSON array of strings; NULL on a summary stored before this column existed
--
-- Not part of ck_alert_ai_summary's all-or-nothing rule, so the summaries already stored stay
-- valid without evidence; it may only ever sit beside a summary, never stand alone.
ALTER TABLE alert ADD COLUMN ai_evidence JSONB;

ALTER TABLE alert ADD CONSTRAINT ck_alert_ai_evidence CHECK (
    ai_evidence IS NULL
    OR (ai_summarized_at IS NOT NULL AND jsonb_typeof(ai_evidence) = 'array')
);
