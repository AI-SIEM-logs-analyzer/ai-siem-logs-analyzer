package com.siem.analyzer.attack;

import java.util.List;

/**
 * A MITRE ATT&CK release as {@link AttackStixReader} read it: only what the dataset tables keep.
 *
 * @param version the release, from the bundle's {@code x-mitre-collection} ({@code 19.2})
 * @param sha256 hex SHA-256 of the bundle's JSON, after decompression
 * @param tactics in matrix order
 * @param techniques current Enterprise techniques and sub-techniques, by ID
 */
public record AttackBundle(
        String version, String sha256, List<Tactic> tactics, List<Technique> techniques) {

    public AttackBundle {
        tactics = List.copyOf(tactics);
        techniques = List.copyOf(techniques);
    }

    /**
     * @param ordinal position in the Enterprise matrix, from 1
     * @param url {@code null} unless it points at attack.mitre.org
     */
    public record Tactic(String id, String name, String shortname, String url, int ordinal) {}

    /**
     * @param parentId the base technique of a sub-technique; {@code null} on a base technique
     * @param url {@code null} unless it points at attack.mitre.org
     * @param tacticIds the tactics the technique serves, in the bundle's order
     */
    public record Technique(
            String id, String name, String parentId, String url, List<String> tacticIds) {

        public Technique {
            tacticIds = List.copyOf(tacticIds);
        }
    }
}
