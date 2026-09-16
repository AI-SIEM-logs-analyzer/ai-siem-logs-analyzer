-- Which log_event rows have reached the derived OpenSearch index, and when.
--
-- Same contract as V1-V6: Flyway owns this DDL, Hibernate validates against it.
--
-- A separate table rather than a column on log_event, because log_event is append-only by
-- design — see the class comment on LogEvent. Indexing progress is bookkeeping about an
-- event, not part of it, and amending the event row to record it would cost the property
-- that makes a dataset assembled from that table reproducible.
--
-- The backlog is the anti-join: log_event rows with no row here. ON DELETE CASCADE keeps
-- that honest if an event is ever removed.
CREATE TABLE log_event_index_state (
    log_event_id BIGINT      PRIMARY KEY,
    -- When the document was accepted by the index. Never NULL: a row exists only once the
    -- write succeeded, so absence of a row is the backlog and there is no third state.
    indexed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_log_event_index_state_event
        FOREIGN KEY (log_event_id) REFERENCES log_event (id) ON DELETE CASCADE
);
