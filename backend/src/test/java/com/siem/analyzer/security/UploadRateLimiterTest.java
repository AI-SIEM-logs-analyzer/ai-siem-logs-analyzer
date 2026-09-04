package com.siem.analyzer.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The counter that keeps one account from flooding the ingestion pipeline. */
@QuarkusTest
class UploadRateLimiterTest {

    @Inject UploadRateLimiter limiter;
    @Inject AppConfig config;

    /** A username of its own per test: the counter is keyed on it and outlives the test. */
    private static String someone() {
        return "upload." + UUID.randomUUID();
    }

    @Test
    void allowsUploadsUpToTheConfiguredLimit() {
        String username = someone();

        for (int request = 0; request < config.upload().rateLimit().requests(); request++) {
            assertNull(limiter.consume(username), "blocked at request " + request);
        }

        assertNotNull(limiter.consume(username));
    }

    @Test
    void reportsHowLongTheCallerHasToWait() {
        String username = someone();
        for (int request = 0; request <= config.upload().rateLimit().requests(); request++) {
            limiter.consume(username);
        }

        Duration wait = limiter.consume(username);

        assertNotNull(wait);
        assertTrue(
                !wait.isNegative() && wait.compareTo(config.upload().rateLimit().window()) <= 0,
                wait.toString());
    }

    @Test
    void countsEachAccountSeparately() {
        String username = someone();
        for (int request = 0; request <= config.upload().rateLimit().requests(); request++) {
            limiter.consume(username);
        }

        // One account spending its allowance must not stop everyone else from uploading.
        assertNull(limiter.consume(someone()));
    }
}
