package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

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

    public Duration consume(String username) {

        String key = PREFIX + (username != null ? username : "anonymous");
        long used = counters.incr(key);
        if (used == 1) {
            keys.expire(key, window);
        }
        if (used <= requests) {
            return null;
        }
        long ttl = keys.ttl(key);

        return Duration.ofSeconds(ttl > 0 ? ttl : window.toSeconds());
    }
}
