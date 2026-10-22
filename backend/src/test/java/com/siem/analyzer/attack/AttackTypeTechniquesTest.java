package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.AttackType;
import java.util.EnumSet;
import org.junit.jupiter.api.Test;

class AttackTypeTechniquesTest {

    @Test
    void everyAttackTypeHasAnExplicitEntry() {

        for (AttackType type : AttackType.values()) {
            assertNotNull(AttackTypeTechniques.of(type), type.name());
        }
    }

    @Test
    void everyMappedIdIsWellFormed() {
        for (String id : AttackTypeTechniques.allTechniqueIds()) {
            assertTrue(AttackStixReader.TECHNIQUE_ID.matcher(id).matches(), id);
        }
    }

    @Test
    void whatTheModelCannotPinDownMapsToNothing() {
        assertEquals(java.util.List.of(), AttackTypeTechniques.of(AttackType.BENIGN));
        assertEquals(java.util.List.of(), AttackTypeTechniques.of(AttackType.OTHER));
        assertEquals(java.util.List.of(), AttackTypeTechniques.of(AttackType.ANOMALOUS_BEHAVIOUR));
    }

    @Test
    void findsTheTypesWhoseTechniquesMatch() {
        assertEquals(
                EnumSet.of(AttackType.BRUTE_FORCE, AttackType.CREDENTIAL_STUFFING),
                AttackTypeTechniques.matching(id -> id.equals("T1110") || id.startsWith("T1110.")));
    }
}
