package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class StatusFilterTest {

    @Test
    void anExactCodeIsARangeOfOne() {
        assertEquals(new StatusFilter(404, 404), StatusFilter.parse("404"));
    }

    @Test
    void aClassCoversItsHundredCodes() {
        assertEquals(new StatusFilter(500, 599), StatusFilter.parse("5xx"));
        assertEquals(new StatusFilter(400, 499), StatusFilter.parse("4XX"));
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertEquals(new StatusFilter(200, 200), StatusFilter.parse(" 200 "));
    }

    @Test
    void refusesACodeOutsideTheHttpRange() {
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("600"));
        assertTrue(exception.getMessage().contains("600"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("99"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("6xx"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("0xx"));
    }

    @Test
    void refusesAnythingElse() {
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("40x"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("abc"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse("-404"));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse(""));
        assertThrows(IllegalArgumentException.class, () -> StatusFilter.parse(null));
    }

    @Test
    void refusesAnInvertedRange() {
        assertThrows(IllegalArgumentException.class, () -> new StatusFilter(500, 400));
    }
}
