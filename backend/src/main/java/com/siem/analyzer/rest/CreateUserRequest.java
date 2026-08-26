package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

/** Body of {@code POST /api/users}. */
public record CreateUserRequest(
        /*
         * Restricted to the characters a login name is safely handled with everywhere it ends
         * up: URLs, log lines, LDAP filters. Widening this later is compatible; narrowing it
         * once accounts exist is not.
         */
        @NotBlank
                @Pattern(
                        regexp = "^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])$",
                        message =
                                "must be 3-64 characters of lower-case letters, digits, dot,"
                                        + " underscore or hyphen, and start and end with a letter"
                                        + " or digit")
                String username,
        @Email @Size(max = 254) String email,
        /*
         * Length is the only password rule enforced here. NIST SP 800-63B asks for a minimum
         * length and for screening against known-breached passwords, and explicitly advises
         * against composition rules, which push users towards predictable substitutions.
         */
        @NotBlank @Size(min = 12, max = 128) String password,
        @NotEmpty(message = "a user must have at least one role") Set<Role> roles) {}
