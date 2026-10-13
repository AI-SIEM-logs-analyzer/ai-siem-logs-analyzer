package com.siem.analyzer.rest;

import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.repo.AlertRepository;
import com.siem.analyzer.service.AlertSummaryService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * The alerts raised by detection, for triage.
 *
 * <p>Readable by every signed-in role, like the event search: a viewer follows the queue even if
 * they cannot work it. Asking a model for a summary is triage work, and spends the provider's
 * quota, so it is for analysts and administrators only.
 */
@Path("/api/alerts")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Alerts", description = "Alerts raised by detection rules and models")
public class AlertResource {

    /** The largest page the listing serves; a bigger request is clamped to it. */
    static final int MAX_SIZE = 100;

    private final AlertRepository alerts;
    private final AlertSummaryService summaries;

    @Inject
    public AlertResource(AlertRepository alerts, AlertSummaryService summaries) {
        this.alerts = alerts;
        this.summaries = summaries;
    }

    /**
     * Lists alerts, newest first.
     *
     * @param size rows per page, clamped to 1..{@value #MAX_SIZE} rather than refused, as the
     *     upload listing does
     */
    @GET
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(
            operationId = "listAlerts",
            summary = "List alerts",
            description =
                    "Newest first. Filters combine with AND; the values of one repeated parameter"
                            + " combine with OR.")
    @APIResponse(responseCode = "200", description = "One page of matching alerts")
    @APIResponse(responseCode = "400", description = "A parameter is malformed")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow reading")
    public PageResponse<AlertResponse> list(
            @Parameter(
                            description = "Restrict to these severities; repeatable",
                            schema =
                                    @Schema(
                                            type = SchemaType.ARRAY,
                                            implementation = Severity.class))
                    @QueryParam("severity")
                    List<String> severities,
            @Parameter(
                            description = "Restrict to these triage statuses; repeatable",
                            schema =
                                    @Schema(
                                            type = SchemaType.ARRAY,
                                            implementation = AlertStatus.class))
                    @QueryParam("status")
                    List<String> statuses,
            @Parameter(description = "Zero-based page index") @QueryParam("page") @DefaultValue("0")
                    int page,
            @Parameter(description = "Rows per page, at most " + MAX_SIZE)
                    @QueryParam("size")
                    @DefaultValue("50")
                    int size) {
        if (page < 0) {
            throw new BadRequestException("page must not be negative");
        }
        int boundedSize = Math.clamp(size, 1, MAX_SIZE);
        AlertRepository.Filter filter =
                new AlertRepository.Filter(
                        parseAll(severities, Severity.class, "severity"),
                        parseAll(statuses, AlertStatus.class, "status"));

        List<AlertResponse> items =
                alerts.search(filter, page, boundedSize).stream().map(AlertResponse::from).toList();
        return new PageResponse<>(items, page, boundedSize, alerts.count(filter));
    }

    @GET
    @Path("/{id}")
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @Operation(operationId = "getAlert", summary = "Get one alert, with the event that raised it")
    @APIResponse(responseCode = "200", description = "The alert")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow reading")
    @APIResponse(responseCode = "404", description = "No alert has that id")
    public AlertResponse get(@PathParam("id") Long id) {
        return alerts.findWithDetails(id)
                .map(AlertResponse::from)
                .orElseThrow(() -> new NotFoundException("no alert with id " + id));
    }

    @POST
    @Path("/{id}/summary")
    @RolesAllowed({"ADMIN", "ANALYST"})
    @Operation(
            operationId = "summarizeAlert",
            summary = "Have the configured LLM summarise an alert",
            description =
                    "Asks the AI provider for a structured reading of the alert (severity, attack"
                            + " type, summary, recommended action) and stores it on the alert,"
                            + " replacing any earlier one. Takes as long as the provider does,"
                            + " typically seconds. The alert's own severity is left as the rule"
                            + " set it.")
    @APIResponse(responseCode = "200", description = "The alert, with its new summary")
    @APIResponse(responseCode = "401", description = "No valid access token")
    @APIResponse(responseCode = "403", description = "The caller's roles do not allow triage")
    @APIResponse(responseCode = "404", description = "No alert has that id")
    @APIResponse(
            responseCode = "502",
            description = "The AI provider failed or gave no usable answer; the alert is unchanged")
    public AlertResponse summarize(@PathParam("id") Long id) {
        return AlertResponse.from(summaries.summarize(id));
    }

    /** Parses a repeated enum parameter case-insensitively; an unknown value is a 400. */
    private static <E extends Enum<E>> Set<E> parseAll(
            List<String> values, Class<E> type, String parameter) {
        Set<E> parsed = EnumSet.noneOf(type);
        if (values == null) {
            return parsed;
        }
        for (String value : values) {
            try {
                parsed.add(Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Unknown " + parameter + ": " + value, e);
            }
        }
        return parsed;
    }
}
