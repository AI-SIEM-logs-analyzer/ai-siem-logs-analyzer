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

/** The loaded ATT&CK tactics and techniques, for the alert filters and the read endpoints. */
@ApplicationScoped
public class AttackCatalog {

    /**
     * A technique as the catalogue lists it.
     *
     * @param technique empty when the loaded dataset does not know {@code id}
     */
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

    /** Every tactic in matrix order. */
    public List<AttackTactic> tactics() {
        return tactics.listInMatrixOrder();
    }

    /** Every technique in the loaded dataset, by ID. */
    public List<Entry> techniques() {
        return techniques.listAllWithTactics().stream()
                .map(technique -> new Entry(technique.getId(), Optional.of(technique)))
                .toList();
    }

    /**
     * The techniques an alert can name: those enabled rules map, and those the attack-type fallback
     * names. Six hundred techniques would make a useless filter; this is the dozen or so that can
     * match anything. An ID the dataset does not know is listed bare.
     */
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
