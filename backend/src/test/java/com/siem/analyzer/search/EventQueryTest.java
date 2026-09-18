package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

class EventQueryTest {

    private static final Instant FROM = Instant.parse("2026-09-01T00:00:00Z");
    private static final Instant TO = Instant.parse("2026-09-02T00:00:00Z");

    @Test
    void keepsEveryFilterItWasGiven() {
        EventQuery query =
                EventQuery.builder()
                        .from(FROM)
                        .to(TO)
                        .sourceIds(Set.of(1L, 2L))
                        .severities(Set.of(Severity.ERROR))
                        .fullText("failed login")
                        .substring("192.168.1.")
                        .size(25)
                        .build();

        assertEquals(FROM, query.from());
        assertEquals(TO, query.to());
        assertEquals(Set.of(1L, 2L), query.sourceIds());
        assertEquals(Set.of(Severity.ERROR), query.severities());
        assertEquals("failed login", query.fullText());
        assertEquals("192.168.1.", query.substring());
        assertEquals(25, query.size());
        assertNull(query.cursor());
    }

    @Test
    void keepsTheIpStatusAndOrderFilters() {
        EventQuery query =
                EventQuery.builder()
                        .srcIps(Set.of(IpFilter.parse("10.0.0.0/8")))
                        .statuses(Set.of(StatusFilter.parse("5xx")))
                        .order(SortOrder.ASC)
                        .build();

        assertEquals(Set.of(IpFilter.parse("10.0.0.0/8")), query.srcIps());
        assertEquals(Set.of(new StatusFilter(500, 599)), query.statuses());
        assertEquals(SortOrder.ASC, query.order());
    }

    @Test
    void defaultsToNoIpOrStatusFilterAndNewestFirst() {
        EventQuery query = EventQuery.builder().order(null).build();

        assertTrue(query.srcIps().isEmpty());
        assertTrue(query.statuses().isEmpty());
        assertEquals(SortOrder.DESC, query.order());
    }

    @Test
    void refusesMoreIpFiltersThanTheCap() {
        Set<IpFilter> tooMany =
                IntStream.range(0, EventQuery.MAX_FILTER_VALUES + 1)
                        .mapToObj(i -> IpFilter.parse("10.0." + (i / 256) + "." + (i % 256)))
                        .collect(Collectors.toSet());

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> EventQuery.builder().srcIps(tooMany).build());
        assertTrue(exception.getMessage().contains("srcIp"));
    }

    @Test
    void refusesMoreStatusFiltersThanTheCap() {
        Set<StatusFilter> tooMany =
                IntStream.range(0, EventQuery.MAX_FILTER_VALUES + 1)
                        .mapToObj(i -> new StatusFilter(100 + i, 100 + i))
                        .collect(Collectors.toSet());

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> EventQuery.builder().statuses(tooMany).build());
        assertTrue(exception.getMessage().contains("status"));
    }

    @Test
    void defaultsToAPageOfFifty() {
        assertEquals(50, EventQuery.builder().build().size());
    }

    @Test
    void refusesAPageLargerThanTheCap() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> EventQuery.builder().size(1001).build());
        assertTrue(exception.getMessage().contains("size"));
    }

    @Test
    void refusesANonPositivePage() {
        assertThrows(IllegalArgumentException.class, () -> EventQuery.builder().size(0).build());
    }

    @Test
    void refusesASubstringLongerThanTheCap() {
        String tooLong = "a".repeat(EventQuery.MAX_SUBSTRING_LENGTH + 1);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> EventQuery.builder().substring(tooLong).build());
        assertTrue(exception.getMessage().contains("substring"));
    }

    @Test
    void refusesAnInvertedTimeRange() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> EventQuery.builder().from(TO).to(FROM).build());
        assertTrue(exception.getMessage().contains("from"));
    }

    @Test
    void treatsBlankTextAsAbsent() {
        EventQuery query = EventQuery.builder().fullText("   ").substring("").build();

        assertNull(query.fullText());
        assertNull(query.substring());
    }

    @Test
    void exposesUnmodifiableFilterSets() {
        EventQuery query = EventQuery.builder().sourceIds(Set.of(1L)).build();

        assertThrows(UnsupportedOperationException.class, () -> query.sourceIds().add(2L));
    }
}
