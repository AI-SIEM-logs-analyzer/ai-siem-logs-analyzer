package com.siem.analyzer.rest;

import jakarta.validation.constraints.NotBlank;

/** Body of {@code POST /api/auth/refresh} and {@code POST /api/auth/logout}. */
public record RefreshRequest(@NotBlank String refreshToken) {}
