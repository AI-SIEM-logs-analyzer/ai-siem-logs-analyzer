package com.siem.analyzer.security;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;

/**
 * Access tokens that must stop being accepted before they expire.
 *
 * <p>An access token is verified from its signature alone, so nothing else can withdraw one. The
 * list stays small on its own: an entry lives exactly as long as the token it names had left, and
 * the whole list is bounded by the sign-outs that happen within one access-token lifetime.
 */
@ApplicationScoped
public class TokenDenyList {

    private static final String PREFIX = "denied:";

    /** The value is irrelevant — presence of the key is the whole signal. */
    private static final String MARKER = "1";

    private final ValueCommands<String, String> values;
    private final KeyCommands<String> keys;

    @Inject
    public TokenDenyList(RedisDataSource redis) {
        this.values = redis.value(String.class);
        this.keys = redis.key();
    }

    /**
     * Denies a token for the rest of its life.
     *
     * @param remaining time until the token's {@code exp}; a non-positive value still buys a
     *     second, because SETEX rejects a TTL of zero and a silently skipped write would leave a
     *     logout that did nothing
     */
    public void deny(String jti, Duration remaining) {
        values.setex(PREFIX + jti, Math.max(1, remaining.toSeconds()), MARKER);
    }

    /** Whether a token has been withdrawn. A token with no {@code jti} is not on the list. */
    public boolean isDenied(String jti) {
        return jti != null && keys.exists(PREFIX + jti);
    }
}
