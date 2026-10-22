package com.siem.analyzer.attack;

import java.util.List;

public record AttackBundle(
        String version, String sha256, List<Tactic> tactics, List<Technique> techniques) {

    public AttackBundle {
        tactics = List.copyOf(tactics);
        techniques = List.copyOf(techniques);
    }

    public record Tactic(String id, String name, String shortname, String url, int ordinal) {}

    public record Technique(
            String id, String name, String parentId, String url, List<String> tacticIds) {

        public Technique {
            tacticIds = List.copyOf(tacticIds);
        }
    }
}
