ALTER TABLE log_upload
    DROP CONSTRAINT ck_log_upload_format;

ALTER TABLE log_upload
    ADD CONSTRAINT ck_log_upload_format
        CHECK (detected_format IS NULL
               OR detected_format IN ('JSON', 'SYSLOG', 'CEF', 'CSV', 'ACCESS_LOG', 'PLAIN'));
