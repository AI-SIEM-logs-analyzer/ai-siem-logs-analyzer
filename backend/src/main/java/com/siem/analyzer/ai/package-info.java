/**
 * LLM assistance for triage, through quarkus-langchain4j.
 *
 * <p>{@link com.siem.analyzer.ai.AlertSummarizer} is a declarative AI service that reads an alert,
 * written by {@link com.siem.analyzer.ai.AlertPrompt}, and answers with structured output: an
 * {@link com.siem.analyzer.ai.AlertSummary} record (severity, attack type, summary, recommended
 * action) that LangChain4j parses from the model's JSON. The model is Anthropic, OpenAI or a local
 * Ollama, chosen at runtime by {@link com.siem.analyzer.ai.ConfiguredChatModel} from {@code
 * app.ai.provider}.
 *
 * <p>Nothing here stores anything; {@link com.siem.analyzer.service.AlertSummaryService} decides
 * when to ask and records the answer on the alert.
 */
package com.siem.analyzer.ai;
