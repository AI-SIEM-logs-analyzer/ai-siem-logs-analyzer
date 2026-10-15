package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;
import com.siem.analyzer.attack.TechniqueSource;
import java.util.List;

/**
 * A MITRE ATT&CK technique an alert evidences.
 *
 * @param id {@code T1110.001}
 * @param name {@code null} when the loaded ATT&CK dataset does not know the ID
 * @param url the technique's page on attack.mitre.org; {@code null} like {@code name}
 * @param tactics the tactics it serves, in matrix order
 * @param source {@code RULE} when the rule that fired is mapped to it, {@code AI} when no rule
 *     fired and it follows from the attack type a model gave the alert
 */
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
