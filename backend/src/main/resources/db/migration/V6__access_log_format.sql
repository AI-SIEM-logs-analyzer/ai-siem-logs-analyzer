-- Adds ACCESS_LOG (Apache / Nginx Common and Combined Log Format) to the formats a log_upload
-- may record.
--
-- Same contract as V1-V5: Flyway owns this DDL, Hibernate validates against it. The list below
-- mirrors the LogFormat enum; a constant missing here fails the insert, not the build.
ALTER TABLE log_upload
    DROP CONSTRAINT ck_log_upload_format;

ALTER TABLE log_upload
    ADD CONSTRAINT ck_log_upload_format
        CHECK (detected_format IS NULL
               OR detected_format IN ('JSON', 'SYSLOG', 'CEF', 'CSV', 'ACCESS_LOG', 'PLAIN'));
