package com.siem.analyzer.rest;

import com.siem.analyzer.search.EventFacets;
import com.siem.analyzer.search.EventHit;
import com.siem.analyzer.search.SearchPage;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * One page of search results, as the API returns it.
 *
 * <p>The cursor is flattened into two scalars so a caller can hand them straight back as query
 * parameters without decoding anything.
 */
public record EventSearchResponse(
        List<Hit> hits,
        long totalHits,
        Instant nextCursorOccurredAt,
        Long nextCursorEventId,
        EventFacets facets) {

    public static EventSearchResponse from(SearchPage page) {
        return new EventSearchResponse(
                page.hits().stream().map(Hit::from).toList(),
                page.totalHits(),
                page.nextCursor() == null ? null : page.nextCursor().occurredAt(),
                page.nextCursor() == null ? null : page.nextCursor().eventId(),
                page.facets());
    }

    /** One matching event. {@code eventId} is the key into PostgreSQL for the full row. */
    public record Hit(
            long eventId,
            long sourceId,
            Instant occurredAt,
            Instant ingestedAt,
            String severity,
            String message,
            String raw,
            Map<String, Object> fields) {

        static Hit from(EventHit hit) {
            return new Hit(
                    hit.eventId(),
                    hit.sourceId(),
                    hit.occurredAt(),
                    hit.ingestedAt(),
                    hit.severity().name(),
                    hit.message(),
                    hit.raw(),
                    hit.fields());
        }
    }
}
