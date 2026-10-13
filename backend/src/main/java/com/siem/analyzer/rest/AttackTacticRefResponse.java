package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;

/** A MITRE ATT&CK tactic a technique serves. */
public record AttackTacticRefResponse(String id, String name) {

    static AttackTacticRefResponse from(AlertTechniqueResolver.TacticRef tactic) {
        return new AttackTacticRefResponse(tactic.id(), tactic.name());
    }
}
