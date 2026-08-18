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
 * A system that produces log events.
 *
 * <p>Column names are spelled out rather than left to the naming strategy, because the migration in
 * {@code db/migration} is the authority for them and a reader should be able to match the two files
 * line by line.
 */
@Entity
@Table(name = "log_source")
public class LogSource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name", nullable = false, unique = true)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private LogSourceType type;

    @Column(name = "hostname")
    private String hostname;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    /**
     * Fills in the creation timestamp.
     *
     * <p>The column carries a {@code DEFAULT now()} for inserts made outside the application, but
     * Hibernate sends every mapped column on insert, so leaving the field null would write a null
     * over that default rather than fall back to it.
     */
    @PrePersist
    void onPersist() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public LogSourceType getType() {
        return type;
    }

    public void setType(LogSourceType type) {
        this.type = type;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
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
}
