package com.siem.analyzer.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

/** Rotation, reuse detection and revocation, against a real Redis. */
@QuarkusTest
class RefreshTokenStoreTest {

    private static final long USER_ID = 4242L;

    @Inject RefreshTokenStore store;
    @Inject RedisDataSource redis;

    @Test
    void issuesAnUnguessableTokenTiedToTheAccount() {
        String family = RefreshTokenStore.newFamily();

        String token = store.issue(USER_ID, family);

        // 32 random bytes, base64url without padding.
        assertEquals(43, token.length());
        assertNotEquals(token, store.issue(USER_ID, family));

        RefreshTokenStore.ConsumeResult result = store.consume(token);
        assertEquals(RefreshTokenStore.Status.ROTATED, result.status());
        assertEquals(USER_ID, result.record().userId());
        assertEquals(family, result.record().family());
    }

    @Test
    void expiresTheStoredRecordWithTheConfiguredLifetime() {
        String token = store.issue(USER_ID, RefreshTokenStore.newFamily());

        long ttl = redis.key().ttl("refresh:" + token);

        assertTrue(ttl > 0, "no TTL on the stored record: " + ttl);
    }

    @Test
    void letsOnlyOneOfTwoConcurrentCallsConsumeAToken() throws Exception {
        String token = store.issue(USER_ID, RefreshTokenStore.newFamily());
        Callable<RefreshTokenStore.ConsumeResult> consume = () -> store.consume(token);

        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<RefreshTokenStore.ConsumeResult>> results =
                    pool.invokeAll(List.of(consume, consume));

            long rotated =
                    results.stream()
                            .map(RefreshTokenStoreTest::get)
                            .filter(r -> r.status() == RefreshTokenStore.Status.ROTATED)
                            .count();
            assertEquals(1, rotated);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void reportsAReplayedTokenAsReuseAndNotAsUnknown() {
        String family = RefreshTokenStore.newFamily();
        String token = store.issue(USER_ID, family);
        store.consume(token);

        RefreshTokenStore.ConsumeResult replay = store.consume(token);

        assertEquals(RefreshTokenStore.Status.REUSED, replay.status());
        // The tombstone carries the family, which is what lets the caller revoke the rest.
        assertEquals(family, replay.record().family());
    }

    @Test
    void reportsATokenItNeverIssuedAsUnknown() {
        assertEquals(
                RefreshTokenStore.Status.UNKNOWN, store.consume("not-a-token-we-issued").status());
    }

    @Test
    void revokesEverySessionOfAnAccountAtOnce() {
        String first = store.issue(USER_ID, RefreshTokenStore.newFamily());
        String second = store.issue(USER_ID, RefreshTokenStore.newFamily());
        store.consume(first);

        store.revokeAllForUser(USER_ID);

        // The live token is gone, and so is the tombstone of the consumed one: after a theft,
        // replaying either must look like nothing rather than like a second alarm.
        assertEquals(RefreshTokenStore.Status.UNKNOWN, store.consume(second).status());
        assertEquals(RefreshTokenStore.Status.UNKNOWN, store.consume(first).status());
    }

    @Test
    void revokesASingleTokenOnLogout() {
        String token = store.issue(USER_ID, RefreshTokenStore.newFamily());

        store.revoke(token);

        assertEquals(RefreshTokenStore.Status.UNKNOWN, store.consume(token).status());
    }

    private static RefreshTokenStore.ConsumeResult get(
            Future<RefreshTokenStore.ConsumeResult> future) {
        try {
            return future.get();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
