package com.siem.analyzer.rest;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;

/**
 * An account as the API returns it.
 *
 * <p>Deliberately not the entity: the password hash must never leave the application, and a
 * hand-written projection is the only way to be sure of that as the entity grows.
 */
public record UserResponse(
        Long id,
        String username,
        String email,
        Set<Role> roles,
        boolean enabled,
        boolean passwordSet,
        Instant createdAt,
        Instant updatedAt) {

    /**
     * Projects an entity.
     *
     * <p>{@code passwordSet} reports whether the account has a usable password without disclosing
     * anything about it; it is false for the seeded administrator until someone sets one.
     */
    public static UserResponse from(User user, boolean passwordSet) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                // Sorted so the JSON is stable between requests, which keeps API responses
                // diffable in tests and in a client cache.
                new TreeSet<>(user.getRoles()),
                user.isEnabled(),
                passwordSet,
                user.getCreatedAt(),
                user.getUpdatedAt());
    }
}
