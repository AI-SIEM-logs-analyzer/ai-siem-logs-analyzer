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

/**
 * Refresh tokens and the state that makes them revocable.
 *
 * <p>The token itself is opaque — 32 random bytes, not a JWT — because it has to be looked up on
 * every use anyway: a signature would be a cost with no benefit. Redis holds three things per
 * token: the live record, a tombstone written when the token is consumed, and membership of the
 * account's family set.
 *
 * <p>The tombstone is what makes reuse detection possible. Once the live record is deleted there is
 * nothing left to tie a replayed token to the sign-in it came from, and a stolen token would look
 * exactly like an expired one.
 */
@ApplicationScoped
public class RefreshTokenStore {

    private static final String LIVE_PREFIX = "refresh:";
    private static final String CONSUMED_PREFIX = "refresh:consumed:";
    private static final String FAMILY_PREFIX = "refresh:user:";

    /** 256 bits of entropy: the token is a bearer credential and is never stretched or hashed. */
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

    /** What {@link #consume} found. */
    public enum Status {
        /** The token was live and has now been exchanged. */
        ROTATED,
        /** The token had already been consumed — treat it as theft. */
        REUSED,
        /** Never issued, or older than the refresh lifetime. */
        UNKNOWN
    }

    /** The outcome of consuming a token; {@code record} is null when the status is UNKNOWN. */
    public record ConsumeResult(Status status, RefreshRecord record) {}

    /** Identifier shared by every token descended from one sign-in. */
    public static String newFamily() {
        return UUID.randomUUID().toString();
    }

    /** Issues a token for an account, in the given family. */
    public String issue(long userId, String family) {
        byte[] raw = new byte[TOKEN_BYTES];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        records.setex(
                LIVE_PREFIX + token,
                ttl.toSeconds(),
                new RefreshRecord(userId, family, Instant.now().getEpochSecond()));
        families.sadd(FAMILY_PREFIX + userId, token);
        // Refreshed on every write, so an account that keeps refreshing keeps its set alive and
        // one that stops leaves nothing behind.
        keys.expire(FAMILY_PREFIX + userId, ttl);

        return token;
    }

    /**
     * Exchanges a token, at most once.
     *
     * <p>{@code GETDEL} is the whole concurrency argument: of two simultaneous callers exactly one
     * receives the record and the other sees an empty key, so a token cannot be spent twice even
     * under a race.
     */
    public ConsumeResult consume(String token) {
        RefreshRecord live = records.getdel(LIVE_PREFIX + token);
        if (live != null) {
            // Membership of the family set is deliberately kept. The token now has a tombstone,
            // and revokeAllForUser walks that set to find and delete it; dropping the membership
            // here would leave the tombstone behind and report the same theft on every replay.
            records.setex(CONSUMED_PREFIX + token, ttl.toSeconds(), live);
            return new ConsumeResult(Status.ROTATED, live);
        }

        RefreshRecord tombstone = records.get(CONSUMED_PREFIX + token);
        if (tombstone != null) {
            return new ConsumeResult(Status.REUSED, tombstone);
        }

        return new ConsumeResult(Status.UNKNOWN, null);
    }

    /** Drops a single token, without leaving a tombstone: a logout is not a theft. */
    public void revoke(String token) {
        RefreshRecord live = records.getdel(LIVE_PREFIX + token);
        if (live != null) {
            families.srem(FAMILY_PREFIX + live.userId(), token);
        }
    }

    /**
     * Drops every token of an account, live and consumed alike.
     *
     * <p>Tombstones go too: after the sessions are cut, a further replay is nothing to act on, and
     * leaving them would report the same theft again on every attempt.
     */
    public void revokeAllForUser(long userId) {
        String familyKey = FAMILY_PREFIX + userId;
        Set<String> tokens = families.smembers(familyKey);
        for (String token : tokens) {
            keys.del(LIVE_PREFIX + token, CONSUMED_PREFIX + token);
        }
        keys.del(familyKey);
    }
}
