package com.siem.analyzer.rest;

import com.siem.analyzer.service.RateLimitedException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/** Turns a throttled sign-in into 429 with the wait the caller has to observe. */
@Provider
public class RateLimitedExceptionMapper implements ExceptionMapper<RateLimitedException> {

    @Override
    public Response toResponse(RateLimitedException exception) {
        return Response.status(429)
                .header("Retry-After", exception.getRetryAfter().toSeconds())
                .type(MediaType.APPLICATION_JSON)
                .entity(
                        Map.of(
                                "error", "too_many_attempts",
                                "message", "too many sign-in attempts, try again later"))
                .build();
    }
}
