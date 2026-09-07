-- Detected format, ingestion progress and the uploader identity for log_upload.
--
-- Same contract as V1-V4: Flyway owns this DDL, Hibernate validates against it.
ALTER TABLE log_upload
    -- NULL means "never analysed": every row written before this migration, and nothing since.
    -- A default would claim a detection that never ran.
    ADD COLUMN detected_format       TEXT,
    -- The uploader as a foreign key, alongside the username text that is already here. The text
    -- stays because it is the historical record: when an account is deleted this column goes NULL
    -- and the name is all that is left to answer "who uploaded this".
    ADD COLUMN uploaded_by_id        BIGINT,
    ADD COLUMN processing_started_at TIMESTAMPTZ,
    ADD COLUMN processed_at          TIMESTAMPTZ,
    -- Events parsed out of the file. Set once, on the move to INGESTED.
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

-- Existing rows carry only the username. Match it back to an account where one still exists.
UPDATE log_upload u
   SET uploaded_by_id = a.id
  FROM app_user a
 WHERE u.uploaded_by = a.username
   AND u.uploaded_by_id IS NULL;

-- The listing filters on status and orders by created_at, so both belong in one index.
CREATE INDEX ix_log_upload_status_created_at ON log_upload (status, created_at DESC);
CREATE INDEX ix_log_upload_uploaded_by_id ON log_upload (uploaded_by_id);
