package com.siem.analyzer.service;

import com.siem.analyzer.domain.AuthEvent;
import com.siem.analyzer.domain.AuthEventType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Transactional;

@ApplicationScoped
public class AuthEventRecorder {

    private final EntityManager entityManager;

    @Inject
    public AuthEventRecorder(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

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
