package com.siem.analyzer.search;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Counts across everything the query matched, not only the page it returned.
 *
 * <p>Each map preserves the order the engine ranked it in, so the caller can show "top N" without
 * sorting again. Every field here is an explicitly mapped one: a value kept in {@code attributes}
 * cannot be aggregated efficiently, which is why the mapping promotes the fields the dashboard
 * needs.
 */
public record EventFacets(
        Map<String, Long> bySeverity,
        Map<String, Long> bySourceId,
        Map<String, Long> byHost,
        Map<String, Long> bySrcIp,
        List<TimeBucket> overTime) {

    public EventFacets {
        bySeverity = copy(bySeverity);
        bySourceId = copy(bySourceId);
        byHost = copy(byHost);
        bySrcIp = copy(bySrcIp);
        overTime = overTime == null ? List.of() : List.copyOf(overTime);
    }

    /** An empty set of facets, for a query that asked for none. */
    public static EventFacets none() {
        return new EventFacets(Map.of(), Map.of(), Map.of(), Map.of(), List.of());
    }

    private static Map<String, Long> copy(Map<String, Long> source) {
        return source == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    /** How many events fell in one interval of the histogram. */
    public record TimeBucket(Instant start, long count) {}
}
