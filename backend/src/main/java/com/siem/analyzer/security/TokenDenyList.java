package com.siem.analyzer.security;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

@ApplicationScoped
public class TokenDenyList {

    private static final String PREFIX = "denied:";

    private static final String MARKER = "1";

    private final ValueCommands<String, String> values;
    private final KeyCommands<String> keys;

    @Inject
    public TokenDenyList(RedisDataSource redis) {
        this.values = redis.value(String.class);
        this.keys = redis.key();
    }

    public void deny(String jti, Duration remaining) {
        values.setex(PREFIX + jti, Math.max(1, remaining.toSeconds()), MARKER);
    }

    public boolean isDenied(String jti) {
        return jti != null && keys.exists(PREFIX + jti);
    }
}
