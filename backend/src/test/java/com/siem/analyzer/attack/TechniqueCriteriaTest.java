package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.domain.AttackType;
import com.siem.analyzer.repo.AlertRepository;
import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Turning the technique filter's values into what the alert query matches. */
class TechniqueCriteriaTest {

    // forTechniques reads no table, so no repository is needed.
    private final TechniqueCriteria criteria = new TechniqueCriteria(null);

    @Test
    void aBaseTechniqueAlsoMatchesItsSubTechniques() {
        AlertRepository.TechniqueCriterion criterion = criteria.forTechniques(Set.of("T1110"));

        assertEquals(Set.of("T1110"), criterion.ids());
        assertEquals(Set.of("T1110"), criterion.bases());
        assertEquals(
                EnumSet.of(AttackType.BRUTE_FORCE, AttackType.CREDENTIAL_STUFFING),
                criterion.attackTypes());
    }

    @Test
    void aSubTechniqueMatchesOnlyItself() {
        AlertRepository.TechniqueCriterion criterion = criteria.forTechniques(Set.of("T1110.004"));

        assertEquals(Set.of("T1110.004"), criterion.ids());
        assertEquals(Set.of(), criterion.bases());
        assertEquals(EnumSet.of(AttackType.CREDENTIAL_STUFFING), criterion.attackTypes());
    }
}
