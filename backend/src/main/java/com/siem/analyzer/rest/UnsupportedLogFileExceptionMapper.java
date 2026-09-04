package com.siem.analyzer.rest;

import com.siem.analyzer.service.UnsupportedLogFileException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/**
 * Turns a file that is not an accepted log file into 415.
 *
 * <p>A mapper of its own rather than letting the framework answer: the exception carries what the
 * endpoint accepts, and a caller that guessed wrong should be told, not handed an empty body.
 */
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
