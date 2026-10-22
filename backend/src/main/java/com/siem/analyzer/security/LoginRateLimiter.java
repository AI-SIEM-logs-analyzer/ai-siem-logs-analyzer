package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

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

    public Duration check(String username, String clientIp) {
        String key = key(username, clientIp);
        Long failures = counters.get(key);
        if (failures == null || failures < attempts) {
            return null;
        }
        long ttl = keys.ttl(key);

        return Duration.ofSeconds(ttl > 0 ? ttl : window.toSeconds());
    }

    public void recordFailure(String username, String clientIp) {
        String key = key(username, clientIp);
        long failures = counters.incr(key);
        if (failures == 1) {
            keys.expire(key, window);
        }
    }

    public void reset(String username, String clientIp) {
        keys.del(key(username, clientIp));
    }

    private static String key(String username, String clientIp) {
        return PREFIX + username + ":" + clientIp;
    }
}
