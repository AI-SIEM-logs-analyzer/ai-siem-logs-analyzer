package com.siem.analyzer.rest;

import jakarta.validation.constraints.NotBlank;

/**
 * Body of {@code POST /api/auth/login}.
 *
 * <p>No format or length constraints beyond presence: this endpoint checks a credential, it does
 * not create one, and a rejection that depended on the shape of the input would tell a caller which
 * usernames are worth trying.
 */
public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
