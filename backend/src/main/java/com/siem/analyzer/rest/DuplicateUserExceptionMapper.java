package com.siem.analyzer.rest;

import com.siem.analyzer.service.DuplicateUserException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/**
 * Turns a unique-value collision into {@code 409 Conflict}.
 *
 * <p>Without this the exception would surface as a 500, which tells a client that the server broke
 * rather than that the request has to change.
 */
@Provider
public class DuplicateUserExceptionMapper implements ExceptionMapper<DuplicateUserException> {

    @Override
    public Response toResponse(DuplicateUserException exception) {
        return Response.status(Response.Status.CONFLICT)
                .type(MediaType.APPLICATION_JSON)
                .entity(Map.of("field", exception.getField(), "message", exception.getMessage()))
                .build();
    }
}
