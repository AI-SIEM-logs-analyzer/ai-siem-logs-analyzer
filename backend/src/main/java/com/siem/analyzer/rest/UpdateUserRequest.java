package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.Set;

public record UpdateUserRequest(
        @Email @Size(max = 254) String email,
        @NotEmpty(message = "a user must have at least one role") Set<Role> roles,
        boolean enabled) {}
