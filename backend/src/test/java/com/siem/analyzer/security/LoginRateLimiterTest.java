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

/** The counter that keeps the sign-in endpoint from being a free guessing oracle. */
@QuarkusTest
class LoginRateLimiterTest {

    private static final String IP = "203.0.113.7";

    @Inject LoginRateLimiter limiter;
    @Inject AppConfig config;

    /** A username of its own per test: the counter is keyed on it and outlives the test. */
    private static String someone() {
        return "rate." + UUID.randomUUID();
    }

    @Test
    void allowsAttemptsUpToTheConfiguredLimit() {
        String username = someone();

        for (int attempt = 0; attempt < config.auth().rateLimit().attempts(); attempt++) {
            assertNull(limiter.check(username, IP), "blocked at attempt " + attempt);
            limiter.recordFailure(username, IP);
        }

        assertNotNull(limiter.check(username, IP));
    }

    @Test
    void reportsHowLongTheCallerHasToWait() {
        String username = someone();
        for (int attempt = 0; attempt < config.auth().rateLimit().attempts(); attempt++) {
            limiter.recordFailure(username, IP);
        }

        Duration wait = limiter.check(username, IP);

        assertNotNull(wait);
        assertTrue(
                !wait.isNegative() && wait.compareTo(config.auth().rateLimit().window()) <= 0,
                wait.toString());
    }

    @Test
    void forgetsTheFailuresAfterASuccessfulSignIn() {
        String username = someone();
        for (int attempt = 0; attempt < config.auth().rateLimit().attempts(); attempt++) {
            limiter.recordFailure(username, IP);
        }

        limiter.reset(username, IP);

        assertNull(limiter.check(username, IP));
    }

    @Test
    void countsEachAddressSeparately() {
        String username = someone();
        for (int attempt = 0; attempt < config.auth().rateLimit().attempts(); attempt++) {
            limiter.recordFailure(username, IP);
        }

        // A blocked account must not become a way to lock everyone else out from elsewhere.
        assertNull(limiter.check(username, "198.51.100.4"));
    }
}
