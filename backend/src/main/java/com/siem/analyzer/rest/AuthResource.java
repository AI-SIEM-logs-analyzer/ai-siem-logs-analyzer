package com.siem.analyzer.rest;

import com.siem.analyzer.domain.User;
import com.siem.analyzer.service.AuthService;
import com.siem.analyzer.service.PasswordService;
import com.siem.analyzer.service.UserService;
import io.quarkus.security.Authenticated;
import io.vertx.core.http.HttpServerRequest;
import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/api/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    private final AuthService auth;
    private final UserService users;
    private final PasswordService passwords;
    private final JsonWebToken jwt;

    @Context HttpServerRequest request;

    @Inject
    public AuthResource(
            AuthService auth, UserService users, PasswordService passwords, JsonWebToken jwt) {
        this.auth = auth;
        this.users = users;
        this.passwords = passwords;
        this.jwt = jwt;
    }

    @POST
    @Path("/login")
    @PermitAll
    public TokenResponse login(@Valid LoginRequest body, @Context HttpHeaders headers) {
        return TokenResponse.from(auth.login(body.username(), body.password(), clientIp(headers)));
    }

    @POST
    @Path("/refresh")
    @PermitAll
    public TokenResponse refresh(@Valid RefreshRequest body, @Context HttpHeaders headers) {
        return TokenResponse.from(auth.refresh(body.refreshToken(), clientIp(headers)));
    }

    @POST
    @Path("/logout")
    @Authenticated
    public Response logout(@Valid RefreshRequest body, @Context HttpHeaders headers) {
        auth.logout(
                body.refreshToken(),
                jwt.getTokenID(),
                Instant.ofEpochSecond(jwt.getExpirationTime()),
                subjectId(),
                jwt.getName(),
                clientIp(headers));
        return Response.noContent().build();
    }

    @GET
    @Path("/me")
    @Authenticated
    public UserResponse me() {
        User user =
                users.findById(subjectId())
                        .orElseThrow(
                                () ->
                                        new NotFoundException(
                                                "the account this token names no longer exists"));
        return UserResponse.from(user, !passwords.isLocked(user.getPasswordHash()));
    }

    private Long subjectId() {
        return Long.valueOf(jwt.getSubject());
    }

    private String clientIp(HttpHeaders headers) {
        String forwarded = headers.getHeaderString("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.remoteAddress() == null ? null : request.remoteAddress().hostAddress();
    }
}
