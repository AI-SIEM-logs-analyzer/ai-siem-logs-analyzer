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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "alert")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @Column(name = "status_changed_at", nullable = false)
    private Instant statusChangedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "group_key")
    private Map<String, Object> groupKey;

    @Column(name = "aggregate_value")
    private BigDecimal aggregateValue;

    @Column(name = "event_count")
    private Integer eventCount;

    @Column(name = "window_start")
    private Instant windowStart;

    @Column(name = "window_end")
    private Instant windowEnd;

    @Enumerated(EnumType.STRING)
    @Column(name = "ai_severity")
    private Severity aiSeverity;

    @Enumerated(EnumType.STRING)
    @Column(name = "ai_attack_type")
    private AttackType aiAttackType;

    @Column(name = "ai_summary")
    private String aiSummary;

    @Column(name = "ai_recommended_action")
    private String aiRecommendedAction;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ai_evidence")
    private List<String> aiEvidence;

    @Column(name = "ai_model")
    private String aiModel;

    @Column(name = "ai_summarized_at")
    private Instant aiSummarizedAt;

    @PrePersist
    void onPersist() {
        if (raisedAt == null) {
            raisedAt = Instant.now();
        }
        if (statusChangedAt == null) {
            statusChangedAt = raisedAt;
        }
    }

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

    public void recordAiSummary(
            Severity severity,
            AttackType attackType,
            String summary,
            String recommendedAction,
            List<String> evidence,
            String model,
            Instant at) {
        aiSeverity = Objects.requireNonNull(severity, "severity");
        aiAttackType = Objects.requireNonNull(attackType, "attackType");
        aiSummary = Objects.requireNonNull(summary, "summary");
        aiRecommendedAction = Objects.requireNonNull(recommendedAction, "recommendedAction");
        aiEvidence = new ArrayList<>(Objects.requireNonNull(evidence, "evidence"));
        aiModel = Objects.requireNonNull(model, "model");
        aiSummarizedAt = Objects.requireNonNull(at, "at");
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

    public Severity getAiSeverity() {
        return aiSeverity;
    }

    public AttackType getAiAttackType() {
        return aiAttackType;
    }

    public String getAiSummary() {
        return aiSummary;
    }

    public String getAiRecommendedAction() {
        return aiRecommendedAction;
    }

    public List<String> getAiEvidence() {
        return aiEvidence;
    }

    public String getAiModel() {
        return aiModel;
    }

    public Instant getAiSummarizedAt() {
        return aiSummarizedAt;
    }
}
