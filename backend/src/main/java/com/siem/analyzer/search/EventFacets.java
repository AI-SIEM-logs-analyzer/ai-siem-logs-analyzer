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
 *
 * <p>{@code byStatus} counts events per HTTP status code; events without one are not counted.
 * {@code topErrors} counts the most frequent messages among ERROR and CRITICAL events, by their
 * exact text. {@code srcIpOverTime} holds, for each address in {@code bySrcIp}, its events per
 * hour, leaving out the hours it has none: how the busiest addresses' activity is spread in time.
 */
public record EventFacets(
        Map<String, Long> bySeverity,
        Map<String, Long> bySourceId,
        Map<String, Long> byHost,
        Map<String, Long> bySrcIp,
        Map<String, Long> byStatus,
        Map<String, Long> topErrors,
        List<TimeBucket> overTime,
        Map<String, List<TimeBucket>> srcIpOverTime) {

    public EventFacets {
        bySeverity = copy(bySeverity);
        bySourceId = copy(bySourceId);
        byHost = copy(byHost);
        bySrcIp = copy(bySrcIp);
        byStatus = copy(byStatus);
        topErrors = copy(topErrors);
        overTime = overTime == null ? List.of() : List.copyOf(overTime);
        srcIpOverTime = copyHistograms(srcIpOverTime);
    }

    /** An empty set of facets, for a query that asked for none. */
    public static EventFacets none() {
        return new EventFacets(
                Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), List.of(), Map.of());
    }

    private static Map<String, Long> copy(Map<String, Long> source) {
        return source == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    private static Map<String, List<TimeBucket>> copyHistograms(
            Map<String, List<TimeBucket>> source) {
        if (source == null) {
            return Map.of();
        }
        Map<String, List<TimeBucket>> copy = new LinkedHashMap<>();
        source.forEach((key, buckets) -> copy.put(key, List.copyOf(buckets)));
        return Collections.unmodifiableMap(copy);
    }

    /** How many events fell in one interval of the histogram. */
    public record TimeBucket(Instant start, long count) {}
}
