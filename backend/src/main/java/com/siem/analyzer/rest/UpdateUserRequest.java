package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;

/**
 * Body of {@code PUT /api/users/{id}}.
 *
 * <p>A full replacement of the mutable fields, not a patch: every field is written as given, so an
 * omitted e-mail address clears it and an omitted role set is rejected. The username and the
 * password are not here — the first is immutable, the second has its own endpoint.
 */
public record UpdateUserRequest(
        @Email @Size(max = 254) String email,
        @NotEmpty(message = "a user must have at least one role") Set<Role> roles,
        boolean enabled) {}
