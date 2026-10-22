package com.siem.analyzer.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.config.AppConfig;
import dev.langchain4j.model.chat.Capability;
import dev.langchain4j.model.chat.ChatModel;
import io.quarkiverse.langchain4j.ModelName;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

@QuarkusTest
class ChatModelProvidersTest {

    @Inject @Any Instance<ChatModel> models;
    @Inject AppConfig config;

    @Test
    void everyProviderHasANamedModel() {
        for (AiProvider provider : AiProvider.values()) {
            assertTrue(
                    models.select(ModelName.Literal.of(provider.configName())).isResolvable(),
                    provider + " has no chat model named " + provider.configName());
        }
    }

    @Test
    void everyProviderEnforcesTheSummarySchema() {

        for (AiProvider provider : AiProvider.values()) {
            assertTrue(
                    model(provider)
                            .supportedCapabilities()
                            .contains(Capability.RESPONSE_FORMAT_JSON_SCHEMA),
                    provider + " does not enforce the JSON schema");
        }
    }

    @Test
    void eachProviderAsksForItsDefaultModel() {
        assertEquals(
                "claude-opus-5-5",
                model(AiProvider.ANTHROPIC).defaultRequestParameters().modelName());
        assertEquals("gpt-5-mini", model(AiProvider.OPENAI).defaultRequestParameters().modelName());
        assertEquals("llama3.2", model(AiProvider.OLLAMA).defaultRequestParameters().modelName());
    }

    @Test
    void anthropicIsTheDefaultProvider() {
        assertEquals(AiProvider.ANTHROPIC, config.ai().provider());
    }

    private ChatModel model(AiProvider provider) {
        return models.select(ModelName.Literal.of(provider.configName())).get();
    }
}
