package com.siem.analyzer.rest;

import com.siem.analyzer.domain.User;
import com.siem.analyzer.service.PasswordService;
import com.siem.analyzer.service.UserService;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.List;

/**
 * Account management over HTTP.
 *
 * <p>Writing is restricted to administrators. Until sign-in existed these endpoints were open, and
 * open they are a full compromise — anyone who can reach them can mint an {@code ADMIN} account or
 * reset any password — so the resource was kept out of production builds with
 * {@code @UnlessBuildProfile}. The role requirement is the lasting protection that replaced it, and
 * the resource now ships in every profile.
 *
 * <p>Reading is open to every signed-in account. That is a deliberate widening: an analyst or a
 * viewer can list every username, e-mail address and role in the system, which is enumeration
 * material for whoever holds the lowest-privileged account. It is accepted because triage needs to
 * know who owns an alert, and it is bounded by what {@link UserResponse} carries — no password
 * hash, no token, nothing that grants access.
 *
 * <p>The roles are stated per method rather than on the class so that adding a method cannot
 * silently inherit the wrong answer. {@code quarkus.security.jaxrs.deny-unannotated-endpoints}
 * refuses an endpoint that states nothing at all, and {@code EndpointAuthorizationCoverageTest}
 * turns that refusal into a build failure instead of a runtime surprise.
 */
@Path("/api/users")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class UserResource {

    private final UserService users;
    private final PasswordService passwords;

    @Inject
    public UserResource(UserService users, PasswordService passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @GET
    public List<UserResponse> list() {
        return users.list().stream().map(this::toResponse).toList();
    }

    @RolesAllowed({"ADMIN", "ANALYST", "VIEWER"})
    @GET
    @Path("/{id}")
    public UserResponse get(@PathParam("id") Long id) {
        return users.findById(id).map(this::toResponse).orElseThrow(() -> notFound(id));
    }

    /** Creates an account and returns it, with a {@code Location} header pointing at it. */
    @RolesAllowed("ADMIN")
    @POST
    public Response create(@Valid CreateUserRequest request, @Context UriInfo uriInfo) {
        User created =
                users.create(
                        request.username(), request.email(), request.password(), request.roles());

        return Response.created(
                        uriInfo.getAbsolutePathBuilder()
                                .path(String.valueOf(created.getId()))
                                .build())
                .entity(toResponse(created))
                .build();
    }

    @RolesAllowed("ADMIN")
    @PUT
    @Path("/{id}")
    public UserResponse update(@PathParam("id") Long id, @Valid UpdateUserRequest request) {
        return users.update(id, request.email(), request.roles(), request.enabled())
                .map(this::toResponse)
                .orElseThrow(() -> notFound(id));
    }

    /**
     * Sets an account's password.
     *
     * <p>Returns no body: there is nothing to say about a password that is safe to say, and the
     * account itself is unchanged from the client's point of view apart from {@code passwordSet}.
     */
    @RolesAllowed("ADMIN")
    @PUT
    @Path("/{id}/password")
    public Response changePassword(@PathParam("id") Long id, @Valid ChangePasswordRequest request) {
        if (!users.changePassword(id, request.password())) {
            throw notFound(id);
        }
        return Response.noContent().build();
    }

    @RolesAllowed("ADMIN")
    @DELETE
    @Path("/{id}")
    public Response delete(@PathParam("id") Long id) {
        if (!users.delete(id)) {
            throw notFound(id);
        }
        return Response.noContent().build();
    }

    private UserResponse toResponse(User user) {
        return UserResponse.from(user, !passwords.isLocked(user.getPasswordHash()));
    }

    private static NotFoundException notFound(Long id) {
        return new NotFoundException("no user with id " + id);
    }
}
