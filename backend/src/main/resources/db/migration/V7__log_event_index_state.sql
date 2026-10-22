CREATE TABLE log_event_index_state (
    log_event_id BIGINT      PRIMARY KEY,
    indexed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_log_event_index_state_event
        FOREIGN KEY (log_event_id) REFERENCES log_event (id) ON DELETE CASCADE
);
