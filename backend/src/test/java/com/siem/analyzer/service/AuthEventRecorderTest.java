package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.siem.analyzer.domain.AuthEvent;
import com.siem.analyzer.domain.AuthEventType;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The audit trail behind every sign-in attempt. */
@QuarkusTest
class AuthEventRecorderTest {

    @Inject AuthEventRecorder recorder;
    @Inject EntityManager entityManager;

    @Test
    void recordsAFailedSignInAgainstAUsernameThatDoesNotExist() {
        String username = "audit." + UUID.randomUUID();

        recorder.record(AuthEventType.LOGIN_FAILURE, username, null, "203.0.113.9", "bad password");

        AuthEvent stored = latestFor(username);
        assertEquals(AuthEventType.LOGIN_FAILURE, stored.getType());
        assertEquals(username, stored.getUsername());
        assertNull(stored.getUserId());
        assertEquals("203.0.113.9", stored.getClientIp());
        assertEquals("bad password", stored.getDetail());
        assertNotNull(stored.getOccurredAt());
    }

    @Test
    void recordsAnEventThatBelongsToAnAccount() {
        String username = "audit." + UUID.randomUUID();

        recorder.record(AuthEventType.LOGIN_SUCCESS, username, 1L, "203.0.113.9", null);

        AuthEvent stored = latestFor(username);
        assertEquals(AuthEventType.LOGIN_SUCCESS, stored.getType());
        assertEquals(1L, stored.getUserId());
    }

    @Transactional
    AuthEvent latestFor(String username) {
        return entityManager
                .createQuery(
                        "select e from AuthEvent e where e.username = ?1"
                                + " order by e.occurredAt desc",
                        AuthEvent.class)
                .setParameter(1, username)
                .setMaxResults(1)
                .getSingleResult();
    }
}
