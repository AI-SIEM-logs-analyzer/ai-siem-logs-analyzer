package com.siem.analyzer.rest;

import com.siem.analyzer.domain.AttackTactic;

/**
 * A MITRE ATT&CK tactic.
 *
 * @param shortname its handle in a technique's kill chain, e.g. {@code credential-access}
 */
public record AttackTacticResponse(String id, String name, String shortname, String url) {

    static AttackTacticResponse from(AttackTactic tactic) {
        return new AttackTacticResponse(
                tactic.getId(), tactic.getName(), tactic.getShortname(), tactic.getUrl());
    }
}
