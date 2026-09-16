package com.siem.analyzer.search;

import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One matching event, as the index returned it.
 *
 * <p>A projection, not an entity: it carries what the result list shows. Anything more comes from
 * PostgreSQL by {@link #eventId()}, which is the authoritative copy.
 */
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

    /** The cursor a caller passes to get the page after this hit. */
    public SearchCursor cursor() {
        return new SearchCursor(occurredAt, eventId);
    }
}
