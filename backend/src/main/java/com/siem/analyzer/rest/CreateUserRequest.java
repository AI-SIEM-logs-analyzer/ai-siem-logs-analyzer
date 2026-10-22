package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

public record CreateUserRequest(
        @NotBlank
                @Pattern(
                        regexp = "^[a-z0-9](?:[a-z0-9._-]{1,62}[a-z0-9])$",
                        message =
                                "must be 3-64 characters of lower-case letters, digits, dot,"
                                        + " underscore or hyphen, and start and end with a letter"
                                        + " or digit")
                String username,
        @Email @Size(max = 254) String email,
        @NotBlank @Size(min = 12, max = 128) String password,
        @NotEmpty(message = "a user must have at least one role") Set<Role> roles) {}
