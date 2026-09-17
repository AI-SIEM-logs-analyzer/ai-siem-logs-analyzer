package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SortOrderTest {

    @Test
    void defaultsToNewestFirst() {
        assertEquals(SortOrder.DESC, SortOrder.parse(null));
        assertEquals(SortOrder.DESC, SortOrder.parse(" "));
    }

    @Test
    void ignoresCase() {
        assertEquals(SortOrder.ASC, SortOrder.parse("asc"));
        assertEquals(SortOrder.DESC, SortOrder.parse("DESC"));
    }

    @Test
    void refusesAnythingElse() {
        assertThrows(IllegalArgumentException.class, () -> SortOrder.parse("newest"));
    }

    @Test
    void speaksTheEngineVocabulary() {
        assertEquals("asc", SortOrder.ASC.engineValue());
        assertEquals("desc", SortOrder.DESC.engineValue());
    }
}
