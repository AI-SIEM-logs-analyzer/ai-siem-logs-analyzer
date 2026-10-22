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

    public AiProvider provider() {
        return config.ai().provider();
    }

    public String describe() {
        String model = get().defaultRequestParameters().modelName();
        String provider = provider().name().toLowerCase(Locale.ROOT);
        return model == null || model.isBlank() ? provider : provider + "/" + model;
    }
}
