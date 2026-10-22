package com.siem.analyzer.rest;

import com.siem.analyzer.service.DuplicateUserException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

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
