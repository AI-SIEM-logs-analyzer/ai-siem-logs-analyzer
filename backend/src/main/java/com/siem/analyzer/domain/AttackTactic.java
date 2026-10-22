package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "attack_tactic")
public class AttackTactic {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "shortname", nullable = false)
    private String shortname;

    @Column(name = "url")
    private String url;

    @Column(name = "ordinal", nullable = false)
    private int ordinal;

    protected AttackTactic() {}

    public AttackTactic(String id, String name, String shortname, String url, int ordinal) {
        this.id = id;
        this.name = name;
        this.shortname = shortname;
        this.url = url;
        this.ordinal = ordinal;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getShortname() {
        return shortname;
    }

    public String getUrl() {
        return url;
    }

    public int getOrdinal() {
        return ordinal;
    }
}
