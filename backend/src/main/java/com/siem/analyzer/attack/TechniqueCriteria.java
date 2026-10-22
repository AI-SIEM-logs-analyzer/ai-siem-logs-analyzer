package com.siem.analyzer.attack;

import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.repo.AlertRepository.TechniqueCriterion;
import com.siem.analyzer.repo.AttackTechniqueRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Set;
import java.util.TreeSet;

@ApplicationScoped
public class TechniqueCriteria {

    private final AttackTechniqueRepository techniques;

    @Inject
    public TechniqueCriteria(AttackTechniqueRepository techniques) {
        this.techniques = techniques;
    }

    public TechniqueCriterion forTechniques(Set<String> ids) {
        Set<String> bases = new TreeSet<>();
        for (String id : ids) {
            if (id.indexOf('.') < 0) {
                bases.add(id);
            }
        }
        Set<AttackType> attackTypes =
                AttackTypeTechniques.matching(id -> ids.contains(id) || bases.contains(baseOf(id)));
        return new TechniqueCriterion(ids, bases, attackTypes);
    }

    public TechniqueCriterion forTactics(Set<String> tacticIds) {
        Set<String> ids = techniques.idsInTactics(tacticIds);
        return new TechniqueCriterion(ids, Set.of(), AttackTypeTechniques.matching(ids::contains));
    }

    private static String baseOf(String id) {
        int dot = id.indexOf('.');
        return dot < 0 ? id : id.substring(0, dot);
    }
}
