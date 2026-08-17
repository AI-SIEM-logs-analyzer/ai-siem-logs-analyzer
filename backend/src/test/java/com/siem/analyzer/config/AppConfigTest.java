package com.siem.analyzer.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

/** Verifies that the {@code app} configuration tree resolves under the {@code test} profile. */
@QuarkusTest
class AppConfigTest {

    @Inject AppConfig appConfig;

    @Test
    void environmentComesFromTheActiveProfile() {
        assertEquals("test", appConfig.environment());
    }

    @Test
    void aiApiKeyResolvesWithoutAnExternalSecret() {
        // Dev and test carry a placeholder so the build never depends on a real secret;
        // prod deliberately has no value in application.yaml and must get one from the
        // environment.
        assertFalse(appConfig.ai().apiKey().isBlank());
    }
}
