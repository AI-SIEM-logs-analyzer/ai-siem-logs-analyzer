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

/**
 * Stores what the rule engine raises and moves alerts through triage.
 *
 * <p>The engine stays free of persistence (see the {@code detect} package): it hands back {@link
 * Detection}s, and this class is where one becomes an {@code alert} row.
 */
@ApplicationScoped
public class AlertService {

    private final AlertRepository alerts;
    private final AlertRuleRepository rules;

    @Inject
    public AlertService(AlertRepository alerts, AlertRuleRepository rules) {
        this.alerts = alerts;
        this.rules = rules;
    }

    /**
     * Stores a detection as a {@link AlertStatus#NEW} alert.
     *
     * <p>The alert takes the rule's name as its title, {@link Detection#summary()} as its detail
     * and the rule's severity, and records the window the rule fired on. An ad-hoc rule, or a
     * stored one deleted since it was compiled, leaves the rule unset rather than failing: the
     * detection happened either way.
     *
     * @param detection what fired
     * @param trigger the stored event the detection's trigger was read from
     */
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

    /**
     * Moves an alert to another status, as {@link AlertStatus#canMoveTo} allows.
     *
     * <p>The row is locked first, so of two analysts closing the same alert at once the second is
     * refused instead of overwriting the first.
     *
     * @throws NotFoundException no alert has that id
     * @throws IllegalAlertTransitionException the alert cannot reach {@code target} from its
     *     current status, which includes already holding it
     */
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
