package com.siem.analyzer.search;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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

    public record TimeBucket(Instant start, long count) {}
}
