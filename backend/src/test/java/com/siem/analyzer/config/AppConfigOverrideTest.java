package com.siem.analyzer.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Verifies that an external configuration source overrides the values baked into application.yaml.
 * The overrides below stand in for the environment variables ({@code APP_ENVIRONMENT}, {@code
 * APP_AI_API_KEY}) used in a deployed environment: both land in config sources that outrank the
 * YAML file, so what this test proves about precedence holds for them too.
 */
@QuarkusTest
@TestProfile(AppConfigOverrideTest.OverrideProfile.class)
class AppConfigOverrideTest {

    @Inject AppConfig appConfig;

    @Test
    void externalConfigurationOverridesApplicationYaml() {
        assertEquals("staging", appConfig.environment());
        assertEquals("secret-from-the-environment", appConfig.ai().apiKey());
    }

    public static class OverrideProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "app.environment", "staging", "app.ai.api-key", "secret-from-the-environment");
        }
    }
}
