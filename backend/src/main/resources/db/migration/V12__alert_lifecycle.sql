ALTER TABLE alert DROP CONSTRAINT ck_alert_status;

UPDATE alert SET status = 'NEW' WHERE status = 'OPEN';
UPDATE alert SET status = 'IN_PROGRESS' WHERE status = 'ACKNOWLEDGED';

ALTER TABLE alert ALTER COLUMN status SET DEFAULT 'NEW';
ALTER TABLE alert ADD CONSTRAINT ck_alert_status CHECK (
    status IN ('NEW', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')
);

UPDATE alert
SET resolved_at = raised_at
WHERE status IN ('RESOLVED', 'FALSE_POSITIVE') AND resolved_at IS NULL;
UPDATE alert
SET resolved_at = NULL
WHERE status NOT IN ('RESOLVED', 'FALSE_POSITIVE');

ALTER TABLE alert ADD CONSTRAINT ck_alert_resolved_at CHECK (
    (status IN ('RESOLVED', 'FALSE_POSITIVE')) = (resolved_at IS NOT NULL)
);

ALTER TABLE alert ADD COLUMN status_changed_at TIMESTAMPTZ;
UPDATE alert SET status_changed_at = COALESCE(resolved_at, raised_at);
ALTER TABLE alert ALTER COLUMN status_changed_at SET NOT NULL;
ALTER TABLE alert ALTER COLUMN status_changed_at SET DEFAULT now();

ALTER TABLE alert ADD COLUMN group_key       JSONB;
ALTER TABLE alert ADD COLUMN aggregate_value NUMERIC;
ALTER TABLE alert ADD COLUMN event_count     INTEGER;
ALTER TABLE alert ADD COLUMN window_start    TIMESTAMPTZ;
ALTER TABLE alert ADD COLUMN window_end      TIMESTAMPTZ;

ALTER TABLE alert ADD CONSTRAINT ck_alert_event_count CHECK (
    event_count IS NULL OR event_count >= 1
);
ALTER TABLE alert ADD CONSTRAINT ck_alert_window CHECK (
    window_start IS NULL OR window_end IS NULL OR window_start <= window_end
);
