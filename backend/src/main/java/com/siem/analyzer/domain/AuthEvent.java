package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One authentication attempt, kept for investigation.
 *
 * <p>Append-only: nothing updates a row here, because an audit trail that can be edited is not one.
 * As with the other entities, column names are spelled out so that this file and {@code
 * db/migration/V3__auth_events.sql} can be read side by side.
 *
 * <p>{@link #userId} is a plain column rather than an association: the account it names may not
 * exist — a failed sign-in against an unknown username has none — and may be deleted later, and a
 * mapped association would insist on neither being true.
 */
@Entity
@Table(name = "auth_event")
public class AuthEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private AuthEventType type;

    @Column(name = "username")
    private String username;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "client_ip")
    private String clientIp;

    @Column(name = "detail")
    private String detail;

    /** Same reason as on {@code User}: Hibernate sends every mapped column, defaults included. */
    @PrePersist
    void onPersist() {
        if (occurredAt == null) {
            occurredAt = Instant.now();
        }
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public AuthEventType getType() {
        return type;
    }

    public void setType(AuthEventType type) {
        this.type = type;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }
}
