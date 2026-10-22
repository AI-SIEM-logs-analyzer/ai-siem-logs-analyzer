package com.siem.analyzer.config;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import java.util.Map;
import org.junit.jupiter.api.Test;

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
