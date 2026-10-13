package com.siem.analyzer.ai;

/**
 * The LLM providers an alert summary can come from, chosen per deployment with {@code
 * app.ai.provider}.
 *
 * <p>Each one is a named LangChain4j model configuration in application.yaml, {@code
 * quarkus.langchain4j.<configName>.chat-model.provider}. The extensions fix which provider backs a
 * name at build time, so all three are built into every image and {@link ConfiguredChatModel} picks
 * one at runtime.
 */
public enum AiProvider {
    ANTHROPIC("summary-anthropic"),
    OPENAI("summary-openai"),
    OLLAMA("summary-ollama");

    private final String configName;

    AiProvider(String configName) {
        this.configName = configName;
    }

    /** The named model configuration, and the {@code @ModelName} of its chat model bean. */
    public String configName() {
        return configName;
    }
}
