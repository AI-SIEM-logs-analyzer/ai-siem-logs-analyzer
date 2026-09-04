package com.siem.analyzer.rest;

import com.siem.analyzer.service.UploadRateLimitedException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/** Turns a throttled upload into 429 with the wait the caller has to observe. */
@Provider
public class UploadRateLimitedExceptionMapper
        implements ExceptionMapper<UploadRateLimitedException> {

    @Override
    public Response toResponse(UploadRateLimitedException exception) {
        return Response.status(429)
                .header("Retry-After", exception.getRetryAfter().toSeconds())
                .type(MediaType.APPLICATION_JSON)
                .entity(
                        Map.of(
                                "error", "too_many_uploads",
                                "message", "too many uploads, try again later"))
                .build();
    }
}
