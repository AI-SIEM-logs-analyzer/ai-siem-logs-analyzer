package com.siem.analyzer.rest;

import com.siem.analyzer.service.PayloadTooLargeException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/** Turns an oversized upload into 413, naming the limit the caller has to stay under. */
@Provider
public class PayloadTooLargeExceptionMapper implements ExceptionMapper<PayloadTooLargeException> {

    @Override
    public Response toResponse(PayloadTooLargeException exception) {
        return Response.status(413)
                .type(MediaType.APPLICATION_JSON)
                .entity(
                        Map.of(
                                "error", "payload_too_large",
                                "message", "uploaded file is larger than the limit",
                                "maxSizeBytes", exception.getMaxSizeBytes()))
                .build();
    }
}
