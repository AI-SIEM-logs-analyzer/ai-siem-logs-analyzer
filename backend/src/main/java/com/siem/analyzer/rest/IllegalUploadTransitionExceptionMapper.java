package com.siem.analyzer.rest;

import com.siem.analyzer.service.IllegalUploadTransitionException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

@Provider
public class IllegalUploadTransitionExceptionMapper
        implements ExceptionMapper<IllegalUploadTransitionException> {

    @Override
    public Response toResponse(IllegalUploadTransitionException exception) {
        return Response.status(Response.Status.CONFLICT)
                .type(MediaType.APPLICATION_JSON)
                .entity(
                        Map.of(
                                "error",
                                "illegal_upload_transition",
                                "message",
                                exception.getMessage(),
                                "status",
                                exception.getFrom().name()))
                .build();
    }
}
