package com.siem.analyzer.security;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * Turns away a request that carries a withdrawn access token.
 *
 * <p>Runs after authentication — the priority is what guarantees that — so the token has already
 * been verified and {@link JsonWebToken} is populated. An anonymous request has no token identifier
 * and passes straight through; whether it is allowed at all is a question for
 * {@code @RolesAllowed}, not for this filter.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 100)
public class RevokedTokenFilter implements ContainerRequestFilter {

    private final SecurityIdentity identity;
    private final TokenDenyList denyList;

    @Inject
    public RevokedTokenFilter(SecurityIdentity identity, TokenDenyList denyList) {
        this.identity = identity;
        this.denyList = denyList;
    }

    @Override
    public void filter(ContainerRequestContext context) {
        if (identity.getPrincipal() instanceof JsonWebToken jwt
                && denyList.isDenied(jwt.getTokenID())) {
            context.abortWith(
                    Response.status(Response.Status.UNAUTHORIZED)
                            .type(MediaType.APPLICATION_JSON)
                            .entity(
                                    Map.of(
                                            "error", "token_revoked",
                                            "message", "this token has been signed out"))
                            .build());
        }
    }
}
