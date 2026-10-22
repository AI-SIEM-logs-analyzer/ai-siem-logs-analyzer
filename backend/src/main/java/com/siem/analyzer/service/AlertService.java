package com.siem.analyzer.service;

import com.siem.analyzer.detect.Detection;
import com.siem.analyzer.detect.DetectionRule;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.repo.AlertRuleRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.NotFoundException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Objects;

@ApplicationScoped
public class AlertService {

    private final AlertRepository alerts;
    private final AlertRuleRepository rules;

    @Inject
    public AlertService(AlertRepository alerts, AlertRuleRepository rules) {
        this.alerts = alerts;
        this.rules = rules;
    }

    @Transactional
    public Alert raise(Detection detection, LogEvent trigger) {
        Objects.requireNonNull(detection, "detection");
        Objects.requireNonNull(trigger, "trigger");
        DetectionRule rule = detection.rule();

        Alert alert = new Alert();
        if (rule.id() != null) {
            rules.findByIdOptional(rule.id()).ifPresent(alert::setRule);
        }
        alert.setLogEvent(trigger);
        alert.setTitle(rule.name());
        alert.setDetail(detection.summary());
        alert.setSeverity(rule.severity());
        alert.setGroupKey(
                detection.group().isEmpty() ? null : new LinkedHashMap<>(detection.group()));
        alert.setAggregateValue(detection.value());
        alert.setEventCount(detection.eventCount());
        alert.setWindowStart(detection.windowStart());
        alert.setWindowEnd(detection.windowEnd());
        alerts.persist(alert);
        return alert;
    }

    @Transactional
    public Alert changeStatus(Long id, AlertStatus target) {
        Objects.requireNonNull(target, "target");
        Alert alert =
                alerts.findByIdForUpdate(id)
                        .orElseThrow(() -> new NotFoundException("no alert with id " + id));
        if (!alert.getStatus().canMoveTo(target)) {
            throw new IllegalAlertTransitionException(id, alert.getStatus(), target);
        }
        alert.changeStatus(target, Instant.now());
        return alert;
    }
}
