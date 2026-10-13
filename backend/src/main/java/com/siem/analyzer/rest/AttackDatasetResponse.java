package com.siem.analyzer.rest;

import com.siem.analyzer.domain.AttackDataset;
import java.time.Instant;

/**
 * The loaded MITRE ATT&CK release.
 *
 * @param sha256 hex SHA-256 of the bundle's JSON
 */
public record AttackDatasetResponse(
        String version, String sha256, int techniqueCount, Instant importedAt) {

    static AttackDatasetResponse from(AttackDataset dataset) {
        return new AttackDatasetResponse(
                dataset.getVersion(),
                dataset.getSha256(),
                dataset.getTechniqueCount(),
                dataset.getImportedAt());
    }
}
