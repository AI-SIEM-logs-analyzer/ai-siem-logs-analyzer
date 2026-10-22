package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AttackVersionsTest {

    @Test
    void comparesEachPartAsANumber() {
        assertTrue(AttackVersions.isOlder("9.0", "18.1"));
        assertTrue(AttackVersions.isOlder("19.2", "19.10"));
        assertFalse(AttackVersions.isOlder("19.2", "19.2"));
        assertFalse(AttackVersions.isOlder("20.0", "19.2"));
    }

    @Test
    void aMissingPartCountsAsZero() {
        assertEquals(0, AttackVersions.compare("19", "19.0"));
        assertTrue(AttackVersions.isOlder("19", "19.1"));
    }

    @Test
    void aPartThatIsNotANumberCountsAsZero() {
        assertTrue(AttackVersions.isOlder("beta", "0.1"));
    }
}
