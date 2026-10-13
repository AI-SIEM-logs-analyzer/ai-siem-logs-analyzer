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

/**
 * Has the configured LLM summarise an alert and records the answer on it.
 *
 * <p>No transaction is held while the model thinks: the alert and its window are read in one, the
 * provider is asked outside any, and the answer is written in another, so a slow provider ties up
 * an HTTP worker but never a database connection or a row lock. A new summary replaces the previous
 * one.
 *
 * <p>An answer is stored only once it is complete and grounded: every value it cites as evidence,
 * and every address it names, has to be in the alert the model was shown ({@link Grounding}).
 */
@ApplicationScoped
public class AlertSummaryService {

    /** Longest summary kept; a model that rambles past it is cut rather than refused. */
    static final int MAX_SUMMARY_CHARS = 2_000;

    /** Longest recommended action kept. */
    static final int MAX_ACTION_CHARS = 1_000;

    /** Most evidence values kept; the schema asks for at most this many. */
    static final int MAX_EVIDENCE = 8;

    /**
     * Longest evidence value kept. A longer one is cut without a marker, so what is kept is still a
     * verbatim piece of the alert.
     */
    static final int MAX_EVIDENCE_CHARS = 300;

    /**
     * Most events of the window read to find the group's; a busy source's window can hold far more
     * than the prompt ever shows.
     */
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

    /**
     * Summarises one alert and stores the summary on it.
     *
     * @return the alert with its new summary, its rule and triggering event loaded
     * @throws NotFoundException no alert has that id
     * @throws AlertSummaryFailedException the provider could not be reached, refused, or answered
     *     with something that is not a usable summary, or cites what the alert does not contain
     */
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

    /**
     * The other events of the alert's window that belong to its group, oldest first: the latest
     * {@link AlertPrompt#MAX_WINDOW_EVENTS} of the triggering event's source between the window's
     * start and end whose fields match the group key. An alert with no window, or one that counted
     * a single event, has none.
     */
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

    /**
     * Whether every group-by field of the alert has the same value on {@code event}. The fields are
     * named as rules name them: a payload key, {@code severity}, or {@code attributes.<key>}.
     */
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

    /**
     * The answer trimmed and capped, or a failure when any part of it is missing.
     *
     * <p>Structured output only guarantees the shape when the provider enforces the schema; a
     * provider that is merely told about it can still leave a field out.
     */
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

    /**
     * The answer, or a failure when it cites a value the alert does not contain.
     *
     * <p>The values are logged, not returned: they are the model's words, and the analyst only
     * needs to know the answer was not trustworthy.
     */
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

    /** Stripped, blank and repeated values dropped, at most {@link #MAX_EVIDENCE}, each capped. */
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
