package com.siem.analyzer.service;

import com.siem.analyzer.ai.AlertPrompt;
import com.siem.analyzer.ai.AlertSummarizer;
import com.siem.analyzer.ai.AlertSummary;
import com.siem.analyzer.ai.ConfiguredChatModel;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.repo.AlertRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.NotFoundException;
import java.time.Instant;
import org.jboss.logging.Logger;

/**
 * Has the configured LLM summarise an alert and records the answer on it.
 *
 * <p>No transaction is held while the model thinks: the alert is read in one, the provider is asked
 * outside any, and the answer is written in another, so a slow provider ties up an HTTP worker but
 * never a database connection or a row lock. A new summary replaces the previous one.
 */
@ApplicationScoped
public class AlertSummaryService {

    /** Longest summary kept; a model that rambles past it is cut rather than refused. */
    static final int MAX_SUMMARY_CHARS = 2_000;

    /** Longest recommended action kept. */
    static final int MAX_ACTION_CHARS = 1_000;

    private static final Logger LOG = Logger.getLogger(AlertSummaryService.class);

    private final AlertRepository alerts;
    private final AlertSummarizer summarizer;
    private final ConfiguredChatModel model;

    @Inject
    public AlertSummaryService(
            AlertRepository alerts, AlertSummarizer summarizer, ConfiguredChatModel model) {
        this.alerts = alerts;
        this.summarizer = summarizer;
        this.model = model;
    }

    /**
     * Summarises one alert and stores the summary on it.
     *
     * @return the alert with its new summary, its rule and triggering event loaded
     * @throws NotFoundException no alert has that id
     * @throws AlertSummaryFailedException the provider could not be reached, refused, or answered
     *     with something that is not a usable summary
     */
    public Alert summarize(Long id) {
        String prompt =
                QuarkusTransaction.requiringNew()
                        .call(
                                () ->
                                        alerts.findWithDetails(id)
                                                .map(AlertPrompt::render)
                                                .orElseThrow(() -> notFound(id)));

        AlertSummary answer;
        String modelName;
        try {
            answer = summarizer.summarize(prompt);
            modelName = model.describe();
        } catch (RuntimeException e) {
            LOG.errorf(e, "Summarising alert %d with %s failed", id, model.provider());
            throw new AlertSummaryFailedException(id, e);
        }
        AlertSummary usable = usable(id, answer);

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
                                                modelName,
                                                at));
        return QuarkusTransaction.requiringNew()
                .call(() -> alerts.findWithDetails(id).orElseThrow(() -> notFound(id)));
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
        return new AlertSummary(
                answer.severity(),
                answer.attackType(),
                cap(answer.summary().strip(), MAX_SUMMARY_CHARS),
                cap(answer.recommendedAction().strip(), MAX_ACTION_CHARS));
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
