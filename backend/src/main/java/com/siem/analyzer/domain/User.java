package com.siem.analyzer.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

/**
 * An account that can sign in to the analyzer.
 *
 * <p>As with the other entities, column names are spelled out rather than left to the naming
 * strategy so that this file and {@code db/migration/V2__users.sql} can be read side by side.
 *
 * <p>The entity never sees a plaintext password: {@link #passwordHash} is written from {@code
 * com.siem.analyzer.service.PasswordService} and is the only form of the credential that exists
 * anywhere in the application.
 */
@Entity
@Table(name = "app_user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "email", unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /**
     * Roles held by this account.
     *
     * <p>Fetched eagerly: the set is small, bounded by the number of constants in {@link Role}, and
     * every authorisation decision needs it, so a lazy collection would only trade one query for
     * two.
     */
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
            name = "user_role",
            joinColumns =
                    @JoinColumn(
                            name = "user_id",
                            foreignKey = @ForeignKey(name = "fk_user_role_user")))
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Set<Role> roles = EnumSet.noneOf(Role.class);

    /**
     * Fills in the timestamps.
     *
     * <p>Both columns carry a {@code DEFAULT now()} for inserts made outside the application, but
     * Hibernate sends every mapped column on insert, so leaving the fields null would write nulls
     * over those defaults rather than fall back to them.
     */
    @PrePersist
    void onPersist() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    /**
     * Replaces the whole role set.
     *
     * <p>The argument is copied rather than kept: Hibernate manages the collection instance it
     * handed out, and swapping in a caller-owned set would either detach it from that management or
     * leave the caller able to mutate persistent state from outside.
     */
    public void setRoles(Set<Role> roles) {
        this.roles.clear();
        this.roles.addAll(roles);
    }

    /** Whether this account holds the given role. */
    public boolean hasRole(Role role) {
        return roles.contains(role);
    }
}
