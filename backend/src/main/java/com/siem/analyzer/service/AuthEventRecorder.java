package com.siem.analyzer.service;

import com.siem.analyzer.domain.AuthEvent;
import com.siem.analyzer.domain.AuthEventType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;

/**
 * Writes the audit trail.
 *
 * <p>Every write runs in a transaction of its own. A refused sign-in is the event most worth
 * keeping and the one most likely to be part of a rolled-back call, and an audit record that
 * disappears with the failure it describes is worse than none: it makes the trail look clean.
 */
@ApplicationScoped
public class AuthEventRecorder {

    private final EntityManager entityManager;

    @Inject
    public AuthEventRecorder(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    /**
     * Records one event.
     *
     * @param username the identifier as submitted, which need not belong to an account
     * @param userId the account it turned out to be, or null
     * @param detail free-text context, or null
     */
    @Transactional(Transactional.TxType.REQUIRES_NEW)
    public void record(
            AuthEventType type, String username, Long userId, String clientIp, String detail) {
        AuthEvent event = new AuthEvent();
        event.setType(type);
        event.setUsername(username);
        event.setUserId(userId);
        event.setClientIp(clientIp);
        event.setDetail(detail);
        entityManager.persist(event);
    }
}
