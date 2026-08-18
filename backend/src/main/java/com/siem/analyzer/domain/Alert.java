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

/** Something worth an analyst's attention, raised from a {@link LogEvent}. */
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
    private AlertStatus status = AlertStatus.OPEN;

    @Column(name = "raised_at", nullable = false)
    private Instant raisedAt;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @PrePersist
    void onPersist() {
        if (raisedAt == null) {
            raisedAt = Instant.now();
        }
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

    public void setStatus(AlertStatus status) {
        this.status = status;
    }

    public Instant getRaisedAt() {
        return raisedAt;
    }

    public Instant getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(Instant resolvedAt) {
        this.resolvedAt = resolvedAt;
    }
}
