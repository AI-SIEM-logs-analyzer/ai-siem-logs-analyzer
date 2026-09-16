package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Records that one {@link LogEvent} has reached the derived search index.
 *
 * <p>Its own table rather than a column on the event, because {@link LogEvent} is append-only:
 * indexing progress is bookkeeping about an event, not part of it. The absence of a row is the
 * backlog, which is why {@link #indexedAt} is never null — a row exists only once the write to the
 * index succeeded.
 */
@Entity
@Table(name = "log_event_index_state")
public class LogEventIndexState {

    /** The event's identifier. Shared with {@code log_event.id}, not generated here. */
    @Id
    @Column(name = "log_event_id")
    private Long logEventId;

    @Column(name = "indexed_at", nullable = false)
    private Instant indexedAt;

    protected LogEventIndexState() {
        // for Hibernate
    }

    public LogEventIndexState(Long logEventId, Instant indexedAt) {
        this.logEventId = logEventId;
        this.indexedAt = indexedAt;
    }

    public Long getLogEventId() {
        return logEventId;
    }

    public Instant getIndexedAt() {
        return indexedAt;
    }
}
