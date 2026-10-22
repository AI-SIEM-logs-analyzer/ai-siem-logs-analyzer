package com.siem.analyzer.rest;

import com.siem.analyzer.attack.AlertTechniqueResolver;
import com.siem.analyzer.attack.AttackStixReader;
import com.siem.analyzer.attack.TechniqueCriteria;
import com.siem.analyzer.domain.Alert;
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
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.SchemaType;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

@Path("/api/alerts")
@Produces(MediaType.APPLICATION_JSON)
@Tag(name = "Alerts", description = "Alerts raised by detection rules and models")
public class AlertResource {

    static final int MAX_SIZE = 100;

    private final AlertRepository alerts;
    private final AlertSummaryService summaries;
    private final AlertTechniqueResolver techniques;
    private final TechniqueCriteria criteria;

    @Inject
    public AlertResource(
            AlertRepository alerts,
            AlertSummaryService summaries,
            AlertTechniqueResolver techniques,
            TechniqueCriteria criteria) {
        this.alerts = alerts;
        this.summaries = summaries;
        this.techniques = techniques;
        this.criteria = criteria;
    }

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
            @Parameter(
                            description =
                                    "Restrict to alerts mapped to these MITRE ATT&CK techniques"
                                            + " (T1110, T1110.001); a technique also matches its"
                                            + " sub-techniques; repeatable",
                            schema =
                                    @Schema(type = SchemaType.ARRAY, implementation = String.class))
                    @QueryParam("technique")
                    List<String> techniqueIds,
            @Parameter(
                            description =
                                    "Restrict to alerts mapped to a technique under these MITRE"
                                            + " ATT&CK tactics (TA0006); repeatable",
                            schema =
                                    @Schema(type = SchemaType.ARRAY, implementation = String.class))
                    @QueryParam("tactic")
                    List<String> tacticIds,
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
        Set<String> wantedTechniques =
                parseIds(techniqueIds, AttackStixReader.TECHNIQUE_ID, "technique");
        Set<String> wantedTactics = parseIds(tacticIds, AttackStixReader.TACTIC_ID, "tactic");
        AlertRepository.Filter filter =
                new AlertRepository.Filter(
                        parseAll(severities, Severity.class, "severity"),
                        parseAll(statuses, AlertStatus.class, "status"),
                        wantedTechniques.isEmpty()
                                ? null
                                : criteria.forTechniques(wantedTechniques),
                        wantedTactics.isEmpty() ? null : criteria.forTactics(wantedTactics));

        List<Alert> rows = alerts.search(filter, page, boundedSize);
        Map<Long, List<AlertTechniqueResolver.ResolvedTechnique>> byAlert =
                techniques.resolve(rows);
        List<AlertResponse> items =
                rows.stream()
                        .map(
                                alert ->
                                        AlertResponse.from(
                                                alert,
                                                byAlert.getOrDefault(alert.getId(), List.of())))
                        .toList();
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
                .map(alert -> AlertResponse.from(alert, techniques.resolve(alert)))
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
        Alert alert = summaries.summarize(id);
        return AlertResponse.from(alert, techniques.resolve(alert));
    }

    private static Set<String> parseIds(List<String> values, Pattern format, String parameter) {
        Set<String> parsed = new TreeSet<>();
        if (values == null) {
            return parsed;
        }
        for (String value : values) {
            String id = value.strip().toUpperCase(Locale.ROOT);
            if (!format.matcher(id).matches()) {
                throw new BadRequestException("Malformed " + parameter + ": " + value);
            }
            parsed.add(id);
        }
        return parsed;
    }

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
