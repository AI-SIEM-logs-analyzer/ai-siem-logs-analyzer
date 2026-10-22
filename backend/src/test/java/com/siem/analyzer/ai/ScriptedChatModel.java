package com.siem.analyzer.ai;

import com.siem.analyzer.config.AppConfig;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.Capability;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.request.ChatRequestParameters;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.model.output.FinishReason;
import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Alternative;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

@Alternative
@Priority(1)
@Singleton
public class ScriptedChatModel extends ConfiguredChatModel {

    public static final String VALID_ANSWER =
            """
            {
              "evidence": ["10.0.0.7", "POST /login 401"],
              "severity": "ERROR",
              "attackType": "BRUTE_FORCE",
              "summary": "Six failed logins from 10.0.0.7 within a minute.",
              "recommendedAction": "Block 10.0.0.7 and check the targeted account."
            }""";

    private final AtomicReference<Function<ChatRequest, String>> script =
            new AtomicReference<>(request -> VALID_ANSWER);
    private final AtomicReference<ChatRequest> lastRequest = new AtomicReference<>();

    private final ChatModel model =
            new ChatModel() {
                @Override
                public ChatResponse doChat(ChatRequest request) {
                    lastRequest.set(request);
                    return ChatResponse.builder()
                            .aiMessage(AiMessage.from(script.get().apply(request)))
                            .modelName("scripted")
                            .finishReason(FinishReason.STOP)
                            .build();
                }

                @Override
                public ChatRequestParameters defaultRequestParameters() {
                    return ChatRequestParameters.builder().modelName("scripted").build();
                }

                @Override
                public Set<Capability> supportedCapabilities() {
                    return Set.of(Capability.RESPONSE_FORMAT_JSON_SCHEMA);
                }
            };

    @Inject
    public ScriptedChatModel(AppConfig config, @Any Instance<ChatModel> models) {
        super(config, models);
    }

    @Override
    public ChatModel get() {
        return model;
    }

    public void script(Function<ChatRequest, String> answer) {
        script.set(answer);
    }

    public void reset() {
        script.set(request -> VALID_ANSWER);
        lastRequest.set(null);
    }

    public ChatRequest lastRequest() {
        return lastRequest.get();
    }
}
