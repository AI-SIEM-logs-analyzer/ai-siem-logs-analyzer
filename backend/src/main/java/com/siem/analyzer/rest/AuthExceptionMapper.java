package com.siem.analyzer.rest;

import com.siem.analyzer.service.InvalidCredentialsException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

/**
 * Turns every refused authentication into the same 401.
 *
 * <p>The exception's message stays on this side of the wire. It distinguishes a wrong password from
 * an unknown account from a replayed refresh token, and each of those is a fact worth having only
 * in the audit trail.
 */
@Provider
public class AuthExceptionMapper implements ExceptionMapper<InvalidCredentialsException> {

    @Override
    public Response toResponse(InvalidCredentialsException exception) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .type(MediaType.APPLICATION_JSON)
                .entity(
                        Map.of(
                                "error", "invalid_credentials",
                                "message", "invalid username or password"))
                .build();
    }
}
