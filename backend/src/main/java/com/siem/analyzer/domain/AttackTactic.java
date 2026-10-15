package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A MITRE ATT&CK Enterprise tactic ({@code TA0006} Credential Access): the adversary's goal a
 * technique serves.
 *
 * <p>Reference data. {@code attack.AttackDatasetService} replaces every row on an import, so
 * nothing outside the dataset tables holds a reference to one.
 */
@Entity
@Table(name = "attack_tactic")
public class AttackTactic {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "name", nullable = false)
    private String name;

    /**
     * The tactic's handle in a technique's {@code kill_chain_phases}, e.g. {@code
     * credential-access}.
     */
    @Column(name = "shortname", nullable = false)
    private String shortname;

    @Column(name = "url")
    private String url;

    /** Position in the Enterprise matrix, from 1, left to right. */
    @Column(name = "ordinal", nullable = false)
    private int ordinal;

    protected AttackTactic() {
        // for JPA
    }

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
