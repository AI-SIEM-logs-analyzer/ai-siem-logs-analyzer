-- The alert triage lifecycle, and what a detection saw when it raised an alert.
--
-- Same contract as V1-V11: Flyway owns this DDL, Hibernate validates against it.
--
-- Statuses become NEW, IN_PROGRESS, RESOLVED and FALSE_POSITIVE. OPEN and ACKNOWLEDGED are
-- renamed in place rather than kept as synonyms, so the column holds one spelling per state and
-- AlertStatus stays a plain mirror of the constraint. Which transitions are allowed is decided
-- in AlertStatus, not here: a CHECK constraint sees one row, never the value it replaces.

ALTER TABLE alert DROP CONSTRAINT ck_alert_status;

UPDATE alert SET status = 'NEW' WHERE status = 'OPEN';
UPDATE alert SET status = 'IN_PROGRESS' WHERE status = 'ACKNOWLEDGED';

ALTER TABLE alert ALTER COLUMN status SET DEFAULT 'NEW';
ALTER TABLE alert ADD CONSTRAINT ck_alert_status CHECK (
    status IN ('NEW', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE')
);

-- resolved_at is when the alert was closed, as RESOLVED or as FALSE_POSITIVE, and is set exactly
-- while it is closed: reopening an alert clears it. Rows written before this migration are
-- brought into line first, a closed alert with no time taking its raised_at.
UPDATE alert
SET resolved_at = raised_at
WHERE status IN ('RESOLVED', 'FALSE_POSITIVE') AND resolved_at IS NULL;
UPDATE alert
SET resolved_at = NULL
WHERE status NOT IN ('RESOLVED', 'FALSE_POSITIVE');

ALTER TABLE alert ADD CONSTRAINT ck_alert_resolved_at CHECK (
    (status IN ('RESOLVED', 'FALSE_POSITIVE')) = (resolved_at IS NOT NULL)
);

-- When the status last changed; raised_at until the first transition. Kept apart from
-- resolved_at because an alert picked up and not yet closed has changed without closing.
ALTER TABLE alert ADD COLUMN status_changed_at TIMESTAMPTZ;
UPDATE alert SET status_changed_at = COALESCE(resolved_at, raised_at);
ALTER TABLE alert ALTER COLUMN status_changed_at SET NOT NULL;
ALTER TABLE alert ALTER COLUMN status_changed_at SET DEFAULT now();

-- What the rule engine saw when it fired (detect.Detection). Nullable: an alert raised by a
-- model has no window behind it, and rows written before this migration have none recorded.
--   group_key       the group-by fields and their values, e.g. {"srcIp": "10.0.0.7"};
--                   NULL for an ungrouped or per-event rule
--   aggregate_value the aggregate that crossed the threshold; 1 for a per-event rule
--   event_count     how many events the window held
--   window_start    the oldest event in the window
--   window_end      the newest, the one whose arrival made the rule fire
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
