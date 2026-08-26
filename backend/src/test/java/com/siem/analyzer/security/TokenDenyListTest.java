package com.siem.analyzer.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The list that makes a logout take effect before the access token expires. */
@QuarkusTest
class TokenDenyListTest {

    @Inject TokenDenyList denyList;
    @Inject RedisDataSource redis;

    @Test
    void deniesATokenOnlyAfterItIsListed() {
        String jti = UUID.randomUUID().toString();
        assertFalse(denyList.isDenied(jti));

        denyList.deny(jti, Duration.ofMinutes(15));

        assertTrue(denyList.isDenied(jti));
    }

    @Test
    void keepsTheEntryOnlyForTheRestOfTheTokensLife() {
        String jti = UUID.randomUUID().toString();

        denyList.deny(jti, Duration.ofMinutes(5));

        long ttl = redis.key().ttl("denied:" + jti);
        assertTrue(ttl > 0 && ttl <= 300, "unexpected TTL: " + ttl);
    }

    @Test
    void stillListsATokenThatIsAboutToExpire() {
        String jti = UUID.randomUUID().toString();

        // A token with no life left is still denied for a second: rounding must not produce a
        // logout that quietly does nothing.
        denyList.deny(jti, Duration.ZERO);

        assertTrue(denyList.isDenied(jti));
        assertEquals(1, redis.key().ttl("denied:" + jti));
    }

    @Test
    void ignoresATokenWithNoIdentifier() {
        assertFalse(denyList.isDenied(null));
    }
}
