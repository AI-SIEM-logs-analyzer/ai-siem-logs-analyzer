package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Map;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * A single log line, as received from a {@link LogSource}.
 *
 * <p>Rows of this type are append-only. Nothing in the application updates one; anything that would
 * amend an event belongs in a table derived from it. That is what makes a dataset assembled from
 * this table reproducible months after the fact.
 */
@Entity
@Table(name = "log_event")
public class LogEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "source_id", nullable = false)
    private LogSource source;

    /**
     * Identifier carried by the upstream record, used to discard replays. Absent for some sources.
     */
    @Column(name = "external_id", unique = true)
    private String externalId;

    /** When the event happened, as reported by the source. */
    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    /** When we stored it. The gap to {@link #occurredAt} is ingestion lag. */
    @Column(name = "ingested_at", nullable = false)
    private Instant ingestedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private Severity severity;

    /** Parsed, human-readable summary. */
    @Column(name = "message", nullable = false)
    private String message;

    /**
     * The original line, exactly as received.
     *
     * <p>Never derived, never rewritten. Model training runs against this, not against the parsed
     * fields, and it is the one value here that cannot be reconstructed later.
     */
    @Column(name = "raw", nullable = false)
    private String raw;

    /** Parsed structured fields, stored as {@code jsonb} so they stay queryable. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "payload")
    private Map<String, Object> payload;

    /**
     * Stamps the ingestion time, for the same reason {@code LogSource} stamps its creation time.
     */
    @PrePersist
    void onPersist() {
        if (ingestedAt == null) {
            ingestedAt = Instant.now();
        }
    }

    public Long getId() {
        return id;
    }

    public LogSource getSource() {
        return source;
    }

    public void setSource(LogSource source) {
        this.source = source;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public void setOccurredAt(Instant occurredAt) {
        this.occurredAt = occurredAt;
    }

    public Instant getIngestedAt() {
        return ingestedAt;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getRaw() {
        return raw;
    }

    public void setRaw(String raw) {
        this.raw = raw;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }
}
