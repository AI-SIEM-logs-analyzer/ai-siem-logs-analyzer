package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.search.EventQuery;
import com.siem.analyzer.search.EventSearch;
import com.siem.analyzer.search.IpFilter;
import com.siem.analyzer.search.SearchCursor;
import com.siem.analyzer.search.SortOrder;
import com.siem.analyzer.search.StatusFilter;
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
import java.util.function.Function;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

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
@Tag(name = "Events", description = "Search over ingested log events")
public class EventSearchResource {

    @Inject EventSearch search;

    @GET
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(
            operationId = "searchEvents",
            summary = "Search events",
            description =
                    "Filters combine with AND; the values of one repeated parameter combine with"
                            + " OR. Results are sorted by event time, with the event id breaking"
                            + " ties, and paged by cursor: pass nextCursorOccurredAt and"
                            + " nextCursorEventId from a response back as cursorOccurredAt and"
                            + " cursorEventId, with the same filters and order, to get the next"
                            + " page. A null next cursor means the last page.")
    @APIResponse(
            responseCode = "200",
            description = "One page of matching events",
            content =
                    @Content(
                            mediaType = MediaType.APPLICATION_JSON,
                            schema = @Schema(implementation = EventSearchResponse.class)))
    @APIResponse(responseCode = "400", description = "A parameter is malformed or exceeds a limit")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow searching")
    @APIResponse(
            responseCode = "503",
            description = "The search index is unreachable; ingestion continues")
    public EventSearchResponse search(
            @Parameter(
                            description = "Earliest event time, inclusive (ISO-8601 instant)",
                            example = "2026-09-01T00:00:00Z")
                    @QueryParam("from")
                    String from,
            @Parameter(
                            description = "Latest event time, exclusive (ISO-8601 instant)",
                            example = "2026-09-02T00:00:00Z")
                    @QueryParam("to")
                    String to,
            @Parameter(description = "Restrict to these log sources; repeatable")
                    @QueryParam("sourceId")
                    List<Long> sourceIds,
            @Parameter(
                            description = "Restrict to these severities; repeatable",
                            schema =
                                    @Schema(
                                            type = SchemaType.ARRAY,
                                            implementation = Severity.class))
                    @QueryParam("severity")
                    List<String> severities,
            @Parameter(
                            description =
                                    "Source IP address or CIDR range, IPv4 or IPv6; repeatable, at"
                                            + " most "
                                            + EventQuery.MAX_FILTER_VALUES,
                            example = "10.0.0.0/8")
                    @QueryParam("srcIp")
                    List<String> srcIps,
            @Parameter(
                            description =
                                    "HTTP status code (404) or class (5xx); repeatable, at most "
                                            + EventQuery.MAX_FILTER_VALUES
                                            + ". Events without a status never match.",
                            example = "5xx")
                    @QueryParam("status")
                    List<String> statuses,
            @Parameter(description = "Full-text search over the message", example = "failed login")
                    @QueryParam("q")
                    String fullText,
            @Parameter(
                            description =
                                    "Literal, case-insensitive substring of the raw line; at most "
                                            + EventQuery.MAX_SUBSTRING_LENGTH
                                            + " characters",
                            example = "192.168.1.")
                    @QueryParam("substring")
                    String substring,
            @Parameter(
                            description = "Direction of the event-time sort",
                            schema =
                                    @Schema(
                                            type = SchemaType.STRING,
                                            enumeration = {"asc", "desc"},
                                            defaultValue = "desc"))
                    @QueryParam("order")
                    String order,
            @Parameter(
                            description = "Hits per page",
                            schema =
                                    @Schema(
                                            type = SchemaType.INTEGER,
                                            minimum = "1",
                                            maximum = "" + EventQuery.MAX_SIZE,
                                            defaultValue = "" + EventQuery.DEFAULT_SIZE))
                    @QueryParam("size")
                    Integer size,
            @Parameter(
                            description =
                                    "Resume after this event time; send together with"
                                            + " cursorEventId")
                    @QueryParam("cursorOccurredAt")
                    String cursorOccurredAt,
            @Parameter(
                            description =
                                    "Resume after this event id; send together with"
                                            + " cursorOccurredAt")
                    @QueryParam("cursorEventId")
                    Long cursorEventId,
            @Parameter(
                            description =
                                    "Also count severities, sources, hosts, source IPs and events"
                                            + " per hour across the whole match")
                    @QueryParam("facets")
                    boolean facets) {

        EventQuery.Builder builder;
        try {
            builder =
                    EventQuery.builder()
                            .from(instant("from", from))
                            .to(instant("to", to))
                            .sourceIds(
                                    sourceIds == null ? Set.of() : new LinkedHashSet<>(sourceIds))
                            .severities(severities(severities))
                            .srcIps(parseAll(srcIps, IpFilter::parse))
                            .statuses(parseAll(statuses, StatusFilter::parse))
                            .fullText(fullText)
                            .substring(substring)
                            .order(SortOrder.parse(order))
                            .withFacets(facets);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage(), e);
        }
        if (size != null) {
            builder.size(size);
        }
        if ((cursorOccurredAt == null) != (cursorEventId == null)) {
            // Half a cursor is a caller bug; resuming from the first page instead would
            // silently repeat results.
            throw new BadRequestException(
                    "cursorOccurredAt and cursorEventId must be sent together");
        }
        if (cursorOccurredAt != null) {
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

    /** Parses a repeated parameter; the parser's IllegalArgumentException becomes a 400. */
    private <T> Set<T> parseAll(List<String> values, Function<String, T> parser) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<T> parsed = new LinkedHashSet<>();
        for (String value : values) {
            parsed.add(parser.apply(value));
        }
        return parsed;
    }
}
