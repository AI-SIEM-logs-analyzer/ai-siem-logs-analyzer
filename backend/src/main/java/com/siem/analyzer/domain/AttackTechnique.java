package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "attack_technique")
public class AttackTechnique {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "parent_id")
    private String parentId;

    @Column(name = "url")
    private String url;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "attack_technique_tactic",
            joinColumns = @JoinColumn(name = "technique_id"),
            inverseJoinColumns = @JoinColumn(name = "tactic_id"))
    private Set<AttackTactic> tactics = new HashSet<>();

    protected AttackTechnique() {}

    public AttackTechnique(
            String id, String name, String parentId, String url, Collection<AttackTactic> tactics) {
        this.id = id;
        this.name = name;
        this.parentId = parentId;
        this.url = url;
        this.tactics = new HashSet<>(tactics);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getParentId() {
        return parentId;
    }

    public String getUrl() {
        return url;
    }

    public Set<AttackTactic> getTactics() {
        return Collections.unmodifiableSet(tactics);
    }
}
