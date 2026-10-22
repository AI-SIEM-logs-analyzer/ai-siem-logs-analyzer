package com.siem.analyzer.attack;

import com.siem.analyzer.domain.AttackTactic;
import com.siem.analyzer.domain.AttackTechnique;
import com.siem.analyzer.repo.AlertRuleRepository;
import com.siem.analyzer.repo.AttackTacticRepository;
import com.siem.analyzer.repo.AttackTechniqueRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

@ApplicationScoped
public class AttackCatalog {

    public record Entry(String id, Optional<AttackTechnique> technique) {}

    private final AttackTacticRepository tactics;
    private final AttackTechniqueRepository techniques;
    private final AlertRuleRepository rules;

    @Inject
    public AttackCatalog(
            AttackTacticRepository tactics,
            AttackTechniqueRepository techniques,
            AlertRuleRepository rules) {
        this.tactics = tactics;
        this.techniques = techniques;
        this.rules = rules;
    }

    public List<AttackTactic> tactics() {
        return tactics.listInMatrixOrder();
    }

    public List<Entry> techniques() {
        return techniques.listAllWithTactics().stream()
                .map(technique -> new Entry(technique.getId(), Optional.of(technique)))
                .toList();
    }

    public List<Entry> techniquesInUse() {
        Set<String> ids = new TreeSet<>(rules.techniqueIdsOfEnabledRules());
        ids.addAll(AttackTypeTechniques.allTechniqueIds());
        Map<String, AttackTechnique> known = new HashMap<>();
        for (AttackTechnique technique : techniques.findWithTactics(ids)) {
            known.put(technique.getId(), technique);
        }
        return ids.stream().map(id -> new Entry(id, Optional.ofNullable(known.get(id)))).toList();
    }
}
