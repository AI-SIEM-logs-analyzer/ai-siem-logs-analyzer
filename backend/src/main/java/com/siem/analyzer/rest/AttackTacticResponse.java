package com.siem.analyzer.rest;

import com.siem.analyzer.domain.AttackTactic;

public record AttackTacticResponse(String id, String name, String shortname, String url) {

    static AttackTacticResponse from(AttackTactic tactic) {
        return new AttackTacticResponse(
                tactic.getId(), tactic.getName(), tactic.getShortname(), tactic.getUrl());
    }
}
