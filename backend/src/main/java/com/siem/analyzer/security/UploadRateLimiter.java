package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

/**
 * Counts uploads per account.
 *
 * <p>Keyed on the account alone, unlike {@link LoginRateLimiter}: an upload is authenticated, so
 * the identity is known and is the thing worth limiting. Adding the address would only let one
 * account buy itself more allowance by moving between networks.
 *
 * <p>Every upload is counted, not only the failures. The cost this guards against is the work a
 * successful upload causes — a stored file, a row, a Kafka event and whatever ingestion does with
 * it — so a caller that succeeds every time is exactly the one that has to be paced.
 *
 * <p>The window is fixed rather than sliding, and the counter's own TTL is the window, for the same
 * reason as the sign-in counter: a sorted set per account would answer "has this account uploaded
 * too much lately" no better.
 */
@ApplicationScoped
public class UploadRateLimiter {

    private static final String PREFIX = "upload:rate:";

    private final ValueCommands<String, Long> counters;
    private final KeyCommands<String> keys;
    private final int requests;
    private final Duration window;

    @Inject
    public UploadRateLimiter(RedisDataSource redis, AppConfig config) {
        this.counters = redis.value(Long.class);
        this.keys = redis.key();
        this.requests = config.upload().rateLimit().requests();
        this.window = config.upload().rateLimit().window();
    }

    /**
     * Charges one upload to this account.
     *
     * <p>Counts first and compares afterwards, so two requests arriving together cannot both read a
     * count below the limit and both be let through.
     *
     * @return null when the upload is allowed, otherwise how long the caller has to wait
     */
    public Duration consume(String username) {
        // The endpoints require a role, so an unauthenticated caller never gets this far; the
        // fallback keeps a null out of the key rather than covering a case that can happen.
        String key = PREFIX + (username != null ? username : "anonymous");
        long used = counters.incr(key);
        if (used == 1) {
            keys.expire(key, window);
        }
        if (used <= requests) {
            return null;
        }
        long ttl = keys.ttl(key);
        // A key with no TTL should not exist; treating it as a full window is the safe reading.
        return Duration.ofSeconds(ttl > 0 ? ttl : window.toSeconds());
    }
}
