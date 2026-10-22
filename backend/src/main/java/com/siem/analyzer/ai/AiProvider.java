package com.siem.analyzer.ai;

public enum AiProvider {
    ANTHROPIC("summary-anthropic"),
    OPENAI("summary-openai"),
    OLLAMA("summary-ollama");

    private final String configName;

    AiProvider(String configName) {
        this.configName = configName;
    }

    public String configName() {
        return configName;
    }
}
