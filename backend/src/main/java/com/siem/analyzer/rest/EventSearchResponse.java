package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.search.EventFacets;
import com.siem.analyzer.search.EventHit;
import com.siem.analyzer.search.SearchPage;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * One page of search results, as the API returns it.
 *
 * <p>The cursor is flattened into two scalars so a caller can hand them straight back as query
 * parameters without decoding anything.
 */
@Schema(name = "EventSearchResponse", description = "One page of matching events")
public record EventSearchResponse(
        List<Hit> hits,
        @Schema(description = "Events matching the filters across all pages") long totalHits,
        @Schema(
                        description =
                                "Send back as cursorOccurredAt for the next page; null on the"
                                        + " last page",
                        nullable = true)
                Instant nextCursorOccurredAt,
        @Schema(
                        description =
                                "Send back as cursorEventId for the next page; null on the last"
                                        + " page",
                        nullable = true)
                Long nextCursorEventId,
        @Schema(description = "Aggregations over the whole match; empty unless facets=true")
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
    @Schema(name = "EventHit", description = "One matching event")
    public record Hit(
            long eventId,
            long sourceId,
            Instant occurredAt,
            Instant ingestedAt,
            @Schema(implementation = Severity.class) String severity,
            String message,
            String raw,
            @Schema(
                            description =
                                    "Standard parsed fields present on this event, in camelCase:"
                                            + " host, srcIp, status, method, path, ..., and when the"
                                            + " source address was enriched: geoCountryIso,"
                                            + " geoCountryName, geoCity, geoLatitude, geoLongitude,"
                                            + " geoAsn, geoAsOrg")
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
