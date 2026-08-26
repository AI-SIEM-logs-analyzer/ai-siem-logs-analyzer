package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

/**
 * Counts failed sign-ins per username and address.
 *
 * <p>Keyed on both, not on either alone: on the username alone, anyone could lock an account out by
 * guessing at it; on the address alone, a shared office address would be spent by one careless
 * user. The pair costs an attacker a fresh address per account.
 *
 * <p>The window is fixed rather than sliding — the counter's own TTL is the window — because the
 * question here is "has this pair failed too often lately", and a sliding window would cost a
 * sorted set per pair to answer it no better.
 */
@ApplicationScoped
public class LoginRateLimiter {

    private static final String PREFIX = "login:attempts:";

    private final ValueCommands<String, Long> counters;
    private final KeyCommands<String> keys;
    private final int attempts;
    private final Duration window;

    @Inject
    public LoginRateLimiter(RedisDataSource redis, AppConfig config) {
        this.counters = redis.value(Long.class);
        this.keys = redis.key();
        this.attempts = config.auth().rateLimit().attempts();
        this.window = config.auth().rateLimit().window();
    }

    /**
     * Whether this pair may attempt a sign-in.
     *
     * @return null when the attempt is allowed, otherwise how long the caller has to wait
     */
    public Duration check(String username, String clientIp) {
        String key = key(username, clientIp);
        Long failures = counters.get(key);
        if (failures == null || failures < attempts) {
            return null;
        }
        long ttl = keys.ttl(key);
        // A key with no TTL should not exist; treating it as a full window is the safe reading.
        return Duration.ofSeconds(ttl > 0 ? ttl : window.toSeconds());
    }

    /** Records one failure, starting the window if this is the first. */
    public void recordFailure(String username, String clientIp) {
        String key = key(username, clientIp);
        long failures = counters.incr(key);
        if (failures == 1) {
            keys.expire(key, window);
        }
    }

    /** Clears the counter after a sign-in that worked. */
    public void reset(String username, String clientIp) {
        keys.del(key(username, clientIp));
    }

    private static String key(String username, String clientIp) {
        return PREFIX + username + ":" + clientIp;
    }
}
