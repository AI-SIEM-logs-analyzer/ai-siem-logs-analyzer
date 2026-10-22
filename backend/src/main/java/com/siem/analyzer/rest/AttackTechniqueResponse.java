package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AttackCatalog;
import com.siem.analyzer.domain.AttackTactic;
import com.siem.analyzer.domain.AttackTechnique;
import java.util.Comparator;
import java.util.List;

public record AttackTechniqueResponse(
        String id,
        String name,
        String parentId,
        String url,
        List<AttackTacticRefResponse> tactics) {

    static AttackTechniqueResponse from(AttackCatalog.Entry entry) {
        if (entry.technique().isEmpty()) {
            return new AttackTechniqueResponse(entry.id(), null, null, null, List.of());
        }
        AttackTechnique technique = entry.technique().get();
        return new AttackTechniqueResponse(
                technique.getId(),
                technique.getName(),
                technique.getParentId(),
                technique.getUrl(),
                technique.getTactics().stream()
                        .sorted(Comparator.comparingInt(AttackTactic::getOrdinal))
                        .map(
                                tactic ->
                                        new AttackTacticRefResponse(
                                                tactic.getId(), tactic.getName()))
                        .toList());
    }
}
