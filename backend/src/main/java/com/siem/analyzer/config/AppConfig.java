package com.siem.analyzer.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

/**
 * Application-owned configuration, rooted at the {@code app} prefix in application.yaml.
 *
 * <p>Everything here is resolved and validated while the application boots, so a missing or
 * malformed value fails the start-up rather than the first request that needs it. Values come from
 * application.yaml, from a local {@code .env} file in dev mode, or from environment variables, in
 * increasing order of precedence.
 */
@ConfigMapping(prefix = "app")
public interface AppConfig {

    /**
     * Name of the environment the application runs in, e.g. {@code dev}, {@code test}, {@code
     * prod}.
     */
    @NotBlank
    String environment();

    @Valid
    Ai ai();

    /** Settings for the AI provider used to analyse logs. */
    interface Ai {

        /**
         * API key for the AI provider.
         *
         * <p>Deliberately has no default and no value under the {@code prod} profile: production
         * has to supply {@code APP_AI_API_KEY} through the environment, and the application refuses
         * to start without it. Dev and test carry a placeholder so neither the dev loop nor CI
         * depends on a real secret.
         */
        @NotBlank
        String apiKey();
    }
}
