ALTER TABLE log_upload
    ADD COLUMN detected_format       TEXT,
    ADD COLUMN uploaded_by_id        BIGINT,
    ADD COLUMN processing_started_at TIMESTAMPTZ,
    ADD COLUMN processed_at          TIMESTAMPTZ,
    ADD COLUMN event_count           BIGINT,
    ADD COLUMN error_message         TEXT,
    ADD COLUMN updated_at            TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE log_upload
    ADD CONSTRAINT ck_log_upload_format
        CHECK (detected_format IS NULL
               OR detected_format IN ('JSON', 'SYSLOG', 'CEF', 'CSV', 'PLAIN'));

ALTER TABLE log_upload
    ADD CONSTRAINT fk_log_upload_user
        FOREIGN KEY (uploaded_by_id) REFERENCES app_user (id) ON DELETE SET NULL;

UPDATE log_upload u
   SET uploaded_by_id = a.id
  FROM app_user a
 WHERE u.uploaded_by = a.username
   AND u.uploaded_by_id IS NULL;

CREATE INDEX ix_log_upload_status_created_at ON log_upload (status, created_at DESC);
CREATE INDEX ix_log_upload_uploaded_by_id ON log_upload (uploaded_by_id);
