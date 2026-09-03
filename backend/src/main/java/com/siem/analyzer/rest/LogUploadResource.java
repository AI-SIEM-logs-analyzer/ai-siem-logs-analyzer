package com.siem.analyzer.rest;

import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.service.LogUploadService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
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

    /** Lists recent log uploads. */
    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @GET
    @Path("/uploads")
    public List<LogUploadResponse> list(@QueryParam("limit") @DefaultValue("50") int limit) {
        int boundedLimit = Math.clamp(limit, 1, 100);
        return uploadService.listRecent(boundedLimit).stream()
                .map(LogUploadResponse::from)
                .toList();
    }

    private static NotFoundException notFound(Long id) {
        return new NotFoundException("no log upload with id " + id);
    }
}
