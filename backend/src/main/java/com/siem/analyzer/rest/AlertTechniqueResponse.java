package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;
import com.siem.analyzer.attack.TechniqueSource;
import java.util.List;

public record AlertTechniqueResponse(
        String id,
        String name,
        String url,
        List<AttackTacticRefResponse> tactics,
        TechniqueSource source) {

    static AlertTechniqueResponse from(AlertTechniqueResolver.ResolvedTechnique technique) {
        return new AlertTechniqueResponse(
                technique.id(),
                technique.name(),
                technique.url(),
                technique.tactics().stream().map(AttackTacticRefResponse::from).toList(),
                technique.source());
    }
}
