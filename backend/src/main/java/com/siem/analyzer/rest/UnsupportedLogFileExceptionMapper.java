package com.siem.analyzer.rest;

import com.siem.analyzer.service.UnsupportedLogFileException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

@Provider
public class UnsupportedLogFileExceptionMapper
        implements ExceptionMapper<UnsupportedLogFileException> {

    @Override
    public Response toResponse(UnsupportedLogFileException exception) {
        return Response.status(415)
                .type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", "unsupported_log_file", "message", exception.getMessage()))
                .build();
    }
}
