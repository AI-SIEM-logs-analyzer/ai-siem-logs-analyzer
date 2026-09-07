package com.siem.analyzer.rest;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import com.siem.analyzer.repo.LogUploadRepository;
import com.siem.analyzer.service.LogUploadService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.core.UriInfo;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import org.jboss.resteasy.reactive.RestForm;
import org.jboss.resteasy.reactive.multipart.FileUpload;

/** Log ingestion upload endpoint under {@code /api/logs}. */
@Path("/api/logs")
@Produces(MediaType.APPLICATION_JSON)
public class LogUploadResource {

    private final LogUploadService uploadService;

    @Inject
    public LogUploadResource(LogUploadService uploadService) {
        this.uploadService = uploadService;
    }

    /**
     * Uploads a log file via multipart form-data, stores it, records its metadata, and publishes an
     * ingestion event to Kafka {@code logs.ingest}.
     */
    @RolesAllowed({"ADMIN", "ANALYST"})
    @POST
    @Path("/upload")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response upload(
            @RestForm("file") FileUpload file,
            @RestForm("sourceId") Long sourceId,
            @RestForm("sourceName") String sourceName,
            @RestForm("sourceType") LogSourceType sourceType,
            @Context SecurityContext securityContext,
            @Context UriInfo uriInfo) {
        String username =
                securityContext.getUserPrincipal() != null
                        ? securityContext.getUserPrincipal().getName()
                        : null;

        LogUpload upload = uploadService.upload(file, sourceId, sourceName, sourceType, username);
        LogUploadResponse response = LogUploadResponse.from(upload);

        return Response.accepted(response)
                .location(
                        uriInfo.getBaseUriBuilder()
                                .path("/api/logs/uploads/" + upload.getId())
                                .build())
                .build();
    }

    /** Retrieves the metadata of a previously uploaded log batch by ID. */
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @GET
    @Path("/uploads/{id}")
    public LogUploadResponse get(@PathParam("id") Long id) {
        return uploadService
                .findById(id)
                .map(LogUploadResponse::from)
                .orElseThrow(() -> notFound(id));
    }

    /**
     * Lists log uploads, newest first, filtered by any combination of the query parameters.
     *
     * <p>{@code from} and {@code to} are ISO-8601 instants, {@code from} inclusive and {@code to}
     * exclusive, so consecutive windows cover the timeline exactly once.
     *
     * @param size rows per page, clamped to 1..100 rather than refused, so a client asking for more
     *     gets the largest page the server will serve instead of an error
     */
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @GET
    @Path("/uploads")
    public PageResponse<LogUploadResponse> list(
            @QueryParam("status") LogUploadStatus status,
            @QueryParam("format") LogFormat format,
            @QueryParam("uploadedBy") String uploadedBy,
            @QueryParam("from") String from,
            @QueryParam("to") String to,
            @QueryParam("page") @DefaultValue("0") int page,
            @QueryParam("size") @DefaultValue("50") int size) {
        if (page < 0) {
            throw new BadRequestException("page must not be negative");
        }
        int boundedSize = Math.clamp(size, 1, 100);

        LogUploadRepository.Filter filter =
                new LogUploadRepository.Filter(
                        status,
                        format,
                        uploadedBy,
                        parseInstant(from, "from"),
                        parseInstant(to, "to"));

        List<LogUploadResponse> items =
                uploadService.search(filter, page, boundedSize).stream()
                        .map(LogUploadResponse::from)
                        .toList();

        return new PageResponse<>(items, page, boundedSize, uploadService.count(filter));
    }

    /**
     * Parses an ISO-8601 query parameter.
     *
     * <p>Done by hand because JAX-RS has no converter for {@link Instant}, and a missing converter
     * would answer 404 for a malformed timestamp — the wrong answer for a request that reached the
     * right resource with a bad argument.
     */
    private static Instant parseInstant(String value, String parameterName) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new BadRequestException(
                    parameterName
                            + " must be an ISO-8601 instant, for example 2026-09-01T00:00:00Z");
        }
    }

    private static NotFoundException notFound(Long id) {
        return new NotFoundException("no log upload with id " + id);
    }
}
