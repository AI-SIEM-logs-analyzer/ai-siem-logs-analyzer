package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;

public record UserResponse(
        Long id,
        String username,
        String email,
        Set<Role> roles,
        boolean enabled,
        boolean passwordSet,
        Instant createdAt,
        Instant updatedAt) {

    public static UserResponse from(User user, boolean passwordSet) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                new TreeSet<>(user.getRoles()),
                user.isEnabled(),
                passwordSet,
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
