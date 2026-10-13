package com.siem.analyzer.ai;

import com.siem.analyzer.config.AppConfig;
import dev.langchain4j.model.chat.ChatModel;
import io.quarkiverse.langchain4j.ModelName;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * The chat model of the provider {@code app.ai.provider} names.
 *
 * <p>quarkus-langchain4j decides at build time which provider backs a model name, so every provider
 * gets a named model of its own (see {@link AiProvider}) and the choice between them is made here,
 * at runtime. Only the selected model is ever created: the others stay unresolved, so their missing
 * API keys or unreachable servers cannot fail a deployment that does not use them.
 *
 * <p>A CDI bean, so {@link AlertSummarizer} gets this instance rather than a fresh one, and tests
 * can stand an alternative in its place.
 */
@ApplicationScoped
public class ConfiguredChatModel implements Supplier<ChatModel> {

    private final AppConfig config;
    private final Instance<ChatModel> models;

    @Inject
    public ConfiguredChatModel(AppConfig config, @Any Instance<ChatModel> models) {
        this.config = config;
        this.models = models;
    }

    @Override
    public ChatModel get() {
        return models.select(ModelName.Literal.of(provider().configName())).get();
    }

    /** The provider summaries come from. */
    public AiProvider provider() {
        return config.ai().provider();
    }

    /**
     * The model the provider is asked for, as {@code provider/model}, recorded with each summary so
     * an analyst can tell which model wrote it.
     */
    public String describe() {
        String model = get().defaultRequestParameters().modelName();
        String provider = provider().name().toLowerCase(Locale.ROOT);
        return model == null || model.isBlank() ? provider : provider + "/" + model;
    }
}
