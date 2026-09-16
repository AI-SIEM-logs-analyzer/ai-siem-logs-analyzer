package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.search.EventQuery;
import com.siem.analyzer.search.EventSearch;
import com.siem.analyzer.search.SearchCursor;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Search over ingested events.
 *
 * <p>Readable by every signed-in role, for the same reason the user listing is: triage needs to see
 * the evidence. Nothing here writes.
 *
 * <p>Results come from the derived index, which trails PostgreSQL by at most one backfill interval.
 * A caller that needs the authoritative row reads it by {@code eventId}.
 */
@Path("/api/events/search")
@Produces(MediaType.APPLICATION_JSON)
public class EventSearchResource {

    @Inject EventSearch search;

    @GET
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    public EventSearchResponse search(
            @QueryParam("from") String from,
            @QueryParam("to") String to,
            @QueryParam("sourceId") List<Long> sourceIds,
            @QueryParam("severity") List<String> severities,
            @QueryParam("q") String fullText,
            @QueryParam("substring") String substring,
            @QueryParam("size") Integer size,
            @QueryParam("cursorOccurredAt") String cursorOccurredAt,
            @QueryParam("cursorEventId") Long cursorEventId,
            @QueryParam("facets") boolean facets) {

        EventQuery.Builder builder =
                EventQuery.builder()
                        .from(instant("from", from))
                        .to(instant("to", to))
                        .sourceIds(sourceIds == null ? Set.of() : new LinkedHashSet<>(sourceIds))
                        .severities(severities(severities))
                        .fullText(fullText)
                        .substring(substring)
                        .withFacets(facets);
        if (size != null) {
            builder.size(size);
        }
        if (cursorOccurredAt != null && cursorEventId != null) {
            builder.cursor(
                    new SearchCursor(instant("cursorOccurredAt", cursorOccurredAt), cursorEventId));
        }

        EventQuery query;
        try {
            // Every bound EventQuery enforces is a limit on what one caller can make the
            // cluster do, so a rejected query is a 400 rather than a 500.
            query = builder.build();
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage(), e);
        }
        return EventSearchResponse.from(search.search(query));
    }

    private Instant instant(String parameter, String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new BadRequestException(
                    parameter + " must be an ISO-8601 instant, for example 2026-09-01T00:00:00Z",
                    e);
        }
    }

    private Set<Severity> severities(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<Severity> parsed = new LinkedHashSet<>();
        for (String value : values) {
            try {
                parsed.add(Severity.valueOf(value.toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Unknown severity: " + value, e);
            }
        }
        return parsed;
    }
}
