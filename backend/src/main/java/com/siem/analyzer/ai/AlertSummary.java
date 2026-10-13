package com.siem.analyzer.ai;

import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.domain.Severity;
import dev.langchain4j.model.output.structured.Description;

/**
 * A model's reading of one alert, as {@link AlertSummarizer} returns it.
 *
 * <p>LangChain4j derives the JSON schema the model answers in from this record, the descriptions
 * included, and parses the answer back into it. Where the provider supports it (Anthropic with
 * {@code response-format: json}, OpenAI with {@code json_schema}, Ollama) the schema is enforced by
 * the provider itself; otherwise it is sent as instructions and the answer parsed all the same.
 */
public record AlertSummary(
        @Description(
                        "How serious the alert is once the evidence is weighed: CRITICAL for an attack"
                                + " that likely succeeded or is ongoing against a sensitive target,"
                                + " ERROR for a real attack attempt, WARNING for probing or a"
                                + " plausible attempt, INFO for activity that is almost certainly"
                                + " benign, DEBUG only for noise")
                Severity severity,
        @Description(
                        "The kind of attack the evidence points to; BENIGN when it looks like a false"
                                + " positive, OTHER when none of the values fits")
                AttackType attackType,
        @Description(
                        "Two to four plain sentences for an analyst: what happened, from where,"
                                + " against what, and why it matters. Name concrete values (address,"
                                + " path, user, counts) taken from the alert")
                String summary,
        @Description(
                        "The next step an analyst should take, concrete and short, for example which"
                                + " address to block, which account to check or which log to review")
                String recommendedAction) {}
