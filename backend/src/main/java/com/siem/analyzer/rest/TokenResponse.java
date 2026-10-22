package com.siem.analyzer.rest;

import com.siem.analyzer.service.AuthService;

public record TokenResponse(
        String accessToken, String refreshToken, String tokenType, long expiresIn) {

    private static final String BEARER = "Bearer";

    public static TokenResponse from(AuthService.Tokens tokens) {
        return new TokenResponse(
                tokens.accessToken(), tokens.refreshToken(), BEARER, tokens.expiresInSeconds());
    }
}
