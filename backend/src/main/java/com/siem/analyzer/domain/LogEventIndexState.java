package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "log_event_index_state")
public class LogEventIndexState {

    @Id
    @Column(name = "log_event_id")
    private Long logEventId;

    @Column(name = "indexed_at", nullable = false)
    private Instant indexedAt;

    protected LogEventIndexState() {}

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
