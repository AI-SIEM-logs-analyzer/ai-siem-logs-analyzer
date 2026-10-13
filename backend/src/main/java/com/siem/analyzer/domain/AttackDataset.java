package com.siem.analyzer.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Which MITRE ATT&CK release the dataset tables hold.
 *
 * <p>One row at most ({@code ck_attack_dataset_single_row}): the tables hold one release at a time,
 * and an import rewrites this row along with them.
 */
@Entity
@Table(name = "attack_dataset")
public class AttackDataset {

    /** The only row's key. */
    public static final short ID = 1;

    @Id
    @Column(name = "id")
    private Short id = ID;

    /** The release, as the bundle's {@code x-mitre-collection} states it ({@code 19.2}). */
    @Column(name = "version", nullable = false)
    private String version;

    @Column(name = "sha256", nullable = false)
    private String sha256;

    @Column(name = "technique_count", nullable = false)
    private int techniqueCount;

    @Column(name = "imported_at", nullable = false)
    private Instant importedAt;

    protected AttackDataset() {
        // for JPA
    }

    public AttackDataset(String version, String sha256, int techniqueCount, Instant importedAt) {
        replace(version, sha256, techniqueCount, importedAt);
    }

    /** Records a new import over this row. */
    public void replace(String version, String sha256, int techniqueCount, Instant importedAt) {
        this.version = version;
        this.sha256 = sha256;
        this.techniqueCount = techniqueCount;
        this.importedAt = importedAt;
    }

    public String getVersion() {
        return version;
    }

    public String getSha256() {
        return sha256;
    }

    public int getTechniqueCount() {
        return techniqueCount;
    }

    public Instant getImportedAt() {
        return importedAt;
    }
}
