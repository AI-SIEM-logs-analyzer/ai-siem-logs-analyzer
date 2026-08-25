package com.siem.analyzer.rest;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Body of {@code PUT /api/users/{id}/password}. */
public record ChangePasswordRequest(@NotBlank @Size(min = 12, max = 128) String password) {}
