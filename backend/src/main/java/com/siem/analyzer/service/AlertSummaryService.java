package com.siem.analyzer.service;

import com.siem.analyzer.ai.AlertPrompt;
import com.siem.analyzer.ai.AlertSummarizer;
import com.siem.analyzer.ai.AlertSummary;
import com.siem.analyzer.ai.ConfiguredChatModel;
import com.siem.analyzer.ai.Grounding;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.repo.LogEventRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jboss.logging.Logger;

@ApplicationScoped
public class AlertSummaryService {

    static final int MAX_SUMMARY_CHARS = 2_000;

    static final int MAX_ACTION_CHARS = 1_000;

    static final int MAX_EVIDENCE = 8;

    static final int MAX_EVIDENCE_CHARS = 300;

    static final int MAX_WINDOW_SCAN = 500;

    private static final Logger LOG = Logger.getLogger(AlertSummaryService.class);

    private final AlertRepository alerts;
    private final LogEventRepository events;
    private final AlertSummarizer summarizer;
    private final ConfiguredChatModel model;

    @Inject
    public AlertSummaryService(
            AlertRepository alerts,
            LogEventRepository events,
            AlertSummarizer summarizer,
            ConfiguredChatModel model) {
        this.alerts = alerts;
        this.events = events;
        this.summarizer = summarizer;
        this.model = model;
    }

    public Alert summarize(Long id) {
        AlertPrompt prompt =
                QuarkusTransaction.requiringNew()
                        .call(
                                () ->
                                        alerts.findWithDetails(id)
                                                .map(alert -> AlertPrompt.of(alert, window(alert)))
                                                .orElseThrow(() -> notFound(id)));

        AlertSummary answer;
        String modelName;
        try {
            answer = summarizer.summarize(prompt.text());
            modelName = model.describe();
        } catch (RuntimeException e) {
            LOG.errorf(e, "Summarising alert %d with %s failed", id, model.provider());
            throw new AlertSummaryFailedException(id, e);
        }
        AlertSummary usable = grounded(id, usable(id, answer), prompt);

        Instant at = Instant.now();
        QuarkusTransaction.requiringNew()
                .run(
                        () ->
                                alerts.findByIdForUpdate(id)
                                        .orElseThrow(() -> notFound(id))
                                        .recordAiSummary(
                                                usable.severity(),
                                                usable.attackType(),
                                                usable.summary(),
                                                usable.recommendedAction(),
                                                usable.evidence(),
                                                modelName,
                                                at));
        return QuarkusTransaction.requiringNew()
                .call(() -> alerts.findWithDetails(id).orElseThrow(() -> notFound(id)));
    }

    List<LogEvent> window(Alert alert) {
        LogEvent trigger = alert.getLogEvent();
        if (trigger == null
                || trigger.getSource() == null
                || alert.getWindowStart() == null
                || alert.getWindowEnd() == null
                || alert.getEventCount() == null
                || alert.getEventCount() <= 1) {
            return List.of();
        }
        Map<String, Object> group = alert.getGroupKey() == null ? Map.of() : alert.getGroupKey();
        List<LogEvent> matching = new ArrayList<>();
        for (LogEvent event :
                events.listForSourceWithin(
                        trigger.getSource().getId(),
                        alert.getWindowStart(),
                        alert.getWindowEnd(),
                        MAX_WINDOW_SCAN)) {
            if (!event.getId().equals(trigger.getId()) && inGroup(event, group)) {
                matching.add(event);
                if (matching.size() == AlertPrompt.MAX_WINDOW_EVENTS) {
                    break;
                }
            }
        }
        Collections.reverse(matching);
        return matching;
    }

    static boolean inGroup(LogEvent event, Map<String, Object> group) {
        for (Map.Entry<String, Object> field : group.entrySet()) {
            Object value = field(event, field.getKey());
            if (value == null || !String.valueOf(value).equals(String.valueOf(field.getValue()))) {
                return false;
            }
        }
        return true;
    }

    private static Object field(LogEvent event, String name) {
        if ("severity".equalsIgnoreCase(name)) {
            return event.getSeverity() == null ? null : event.getSeverity().name();
        }
        Map<String, Object> payload = event.getPayload();
        if (payload == null) {
            return null;
        }
        if (payload.containsKey(name)) {
            return payload.get(name);
        }
        String prefix = "attributes.";
        if (name.startsWith(prefix) && payload.get("attributes") instanceof Map<?, ?> attributes) {
            return attributes.get(name.substring(prefix.length()));
        }
        return null;
    }

    static AlertSummary usable(Long id, AlertSummary answer) {
        if (answer == null
                || answer.severity() == null
                || answer.attackType() == null
                || isBlank(answer.summary())
                || isBlank(answer.recommendedAction())) {
            throw new AlertSummaryFailedException(id, "the model's answer is incomplete");
        }
        List<String> evidence = evidence(answer.evidence());
        if (evidence.isEmpty()) {
            throw new AlertSummaryFailedException(id, "the model's answer cites no evidence");
        }
        return new AlertSummary(
                evidence,
                answer.severity(),
                answer.attackType(),
                cap(answer.summary().strip(), MAX_SUMMARY_CHARS),
                cap(answer.recommendedAction().strip(), MAX_ACTION_CHARS));
    }

    static AlertSummary grounded(Long id, AlertSummary answer, AlertPrompt prompt) {
        List<String> ungrounded = Grounding.ungrounded(answer, prompt);
        if (!ungrounded.isEmpty()) {
            LOG.warnf(
                    "The summary of alert %d cites values the alert does not contain: %s",
                    id, ungrounded);
            throw AlertSummaryFailedException.ungrounded(id);
        }
        return answer;
    }

    private static List<String> evidence(List<String> values) {
        if (values == null) {
            return List.of();
        }
        Set<String> kept = new LinkedHashSet<>();
        values.stream()
                .filter(Objects::nonNull)
                .map(String::strip)
                .filter(value -> !value.isEmpty())
                .map(
                        value ->
                                value.length() <= MAX_EVIDENCE_CHARS
                                        ? value
                                        : value.substring(0, MAX_EVIDENCE_CHARS))
                .forEach(kept::add);
        return kept.stream().limit(MAX_EVIDENCE).toList();
    }

    private static boolean isBlank(String text) {
        return text == null || text.isBlank();
    }

    private static String cap(String text, int max) {
        return text.length() <= max ? text : text.substring(0, max - 1) + "…";
    }

    private static NotFoundException notFound(Long id) {
        return new NotFoundException("no alert with id " + id);
    }
}
