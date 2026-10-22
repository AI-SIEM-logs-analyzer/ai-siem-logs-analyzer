package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.redis.datasource.keys.KeyCommands;
import io.quarkus.redis.datasource.set.SetCommands;
import io.quarkus.redis.datasource.value.ValueCommands;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@ApplicationScoped
public class RefreshTokenStore {

    private static final String LIVE_PREFIX = "refresh:";
    private static final String CONSUMED_PREFIX = "refresh:consumed:";
    private static final String FAMILY_PREFIX = "refresh:user:";

    private static final int TOKEN_BYTES = 32;

    private final ValueCommands<String, RefreshRecord> records;
    private final SetCommands<String, String> families;
    private final KeyCommands<String> keys;
    private final SecureRandom random = new SecureRandom();
    private final Duration ttl;

    @Inject
    public RefreshTokenStore(RedisDataSource redis, AppConfig config) {
        this.records = redis.value(RefreshRecord.class);
        this.families = redis.set(String.class);
        this.keys = redis.key();
        this.ttl = config.auth().refreshTtl();
    }

    public enum Status {
        ROTATED,

        REUSED,

        UNKNOWN
    }

    public record ConsumeResult(Status status, RefreshRecord record) {}

    public static String newFamily() {
        return UUID.randomUUID().toString();
    }

    public String issue(long userId, String family) {
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        records.setex(
                LIVE_PREFIX + token,
                ttl.toSeconds(),
                new RefreshRecord(userId, family, Instant.now().getEpochSecond()));
        families.sadd(FAMILY_PREFIX + userId, token);

        keys.expire(FAMILY_PREFIX + userId, ttl);

        return token;
    }

    public ConsumeResult consume(String token) {
        RefreshRecord live = records.getdel(LIVE_PREFIX + token);
        if (live != null) {

            records.setex(CONSUMED_PREFIX + token, ttl.toSeconds(), live);
            return new ConsumeResult(Status.ROTATED, live);
        }

        RefreshRecord tombstone = records.get(CONSUMED_PREFIX + token);
        if (tombstone != null) {
            return new ConsumeResult(Status.REUSED, tombstone);
        }

        return new ConsumeResult(Status.UNKNOWN, null);
    }

    public void revoke(String token) {
        RefreshRecord live = records.getdel(LIVE_PREFIX + token);
        if (live != null) {
            families.srem(FAMILY_PREFIX + live.userId(), token);
        }
    }

    public void revokeAllForUser(long userId) {
        String familyKey = FAMILY_PREFIX + userId;
        Set<String> tokens = families.smembers(familyKey);
        for (String token : tokens) {
            keys.del(LIVE_PREFIX + token, CONSUMED_PREFIX + token);
        }
        keys.del(familyKey);
    }
}
