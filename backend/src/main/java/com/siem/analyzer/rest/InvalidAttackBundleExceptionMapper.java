package com.siem.analyzer.rest;

import com.siem.analyzer.attack.InvalidAttackBundleException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

@Provider
public class InvalidAttackBundleExceptionMapper
        implements ExceptionMapper<InvalidAttackBundleException> {

    @Override
    public Response toResponse(InvalidAttackBundleException exception) {
        return Response.status(Response.Status.BAD_REQUEST)
                .type(MediaType.APPLICATION_JSON)
                .entity(Map.of("error", "invalid_attack_bundle", "message", exception.getMessage()))
                .build();
    }
}
