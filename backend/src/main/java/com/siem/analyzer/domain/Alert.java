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
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

/**
 * Something worth an analyst's attention, raised from a {@link LogEvent}.
 *
 * <p>The status only moves through {@link #changeStatus}, which keeps {@code resolved_at} and
 * {@code status_changed_at} in step with it; {@link AlertStatus} decides which moves are allowed.
 */
@Entity
@Table(name = "alert")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * The rule that fired, when there was one.
     *
     * <p>Optional on purpose: an alert raised by a model has no rule behind it, and the column has
     * been nullable since the first migration so that case needs no schema change.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "rule_id")
    private AlertRule rule;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "log_event_id", nullable = false)
    private LogEvent logEvent;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "detail")
    private String detail;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private AlertStatus status = AlertStatus.NEW;

    @Column(name = "raised_at", nullable = false)
    private Instant raisedAt;

    /** When the alert was closed, as resolved or as a false positive; cleared on reopening. */
    @Column(name = "resolved_at")
    private Instant resolvedAt;

    /** When the status last changed; the raise time until the first transition. */
    @Column(name = "status_changed_at", nullable = false)
    private Instant statusChangedAt;

    /** The group-by fields and their values; {@code null} for an ungrouped or per-event rule. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "group_key")
    private Map<String, Object> groupKey;

    /** The aggregate that crossed the rule's threshold; 1 for a per-event rule. */
    @Column(name = "aggregate_value")
    private BigDecimal aggregateValue;

    /** How many events the rule's window held when it fired. */
    @Column(name = "event_count")
    private Integer eventCount;

    @Column(name = "window_start")
    private Instant windowStart;

    @Column(name = "window_end")
    private Instant windowEnd;

    @PrePersist
    void onPersist() {
        if (raisedAt == null) {
            raisedAt = Instant.now();
        }
        if (statusChangedAt == null) {
            statusChangedAt = raisedAt;
        }
    }

    /**
     * Moves the alert to another status at {@code at}.
     *
     * <p>Closing it stamps {@code resolved_at}; reopening it clears that again.
     *
     * @throws IllegalStateException {@link AlertStatus#canMoveTo} refuses the move
     */
    public void changeStatus(AlertStatus target, Instant at) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(at, "at");
        if (!status.canMoveTo(target)) {
            throw new IllegalStateException(
                    "alert " + id + " cannot move from " + status + " to " + target);
        }
        status = target;
        statusChangedAt = at;
        resolvedAt = target.isClosed() ? at : null;
    }

    public Long getId() {
        return id;
    }

    public AlertRule getRule() {
        return rule;
    }

    public void setRule(AlertRule rule) {
        this.rule = rule;
    }

    public LogEvent getLogEvent() {
        return logEvent;
    }

    public void setLogEvent(LogEvent logEvent) {
        this.logEvent = logEvent;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public AlertStatus getStatus() {
        return status;
    }

    public Instant getRaisedAt() {
        return raisedAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public Instant getStatusChangedAt() {
        return statusChangedAt;
    }

    public Map<String, Object> getGroupKey() {
        return groupKey;
    }

    public void setGroupKey(Map<String, Object> groupKey) {
        this.groupKey = groupKey;
    }

    public BigDecimal getAggregateValue() {
        return aggregateValue;
    }

    public void setAggregateValue(BigDecimal aggregateValue) {
        this.aggregateValue = aggregateValue;
    }

    public Integer getEventCount() {
        return eventCount;
    }

    public void setEventCount(Integer eventCount) {
        this.eventCount = eventCount;
    }

    public Instant getWindowStart() {
        return windowStart;
    }

    public void setWindowStart(Instant windowStart) {
        this.windowStart = windowStart;
    }

    public Instant getWindowEnd() {
        return windowEnd;
    }

    public void setWindowEnd(Instant windowEnd) {
        this.windowEnd = windowEnd;
    }
}
