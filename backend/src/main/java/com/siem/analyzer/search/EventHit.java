package com.siem.analyzer.search;

import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public record EventHit(
        long eventId,
        long sourceId,
        Instant occurredAt,
        Instant ingestedAt,
        Severity severity,
        String message,
        String raw,
        Map<String, Object> fields) {

    public EventHit {
        fields =
                fields == null
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    public SearchCursor cursor() {
        return new SearchCursor(occurredAt, eventId);
    }
}
