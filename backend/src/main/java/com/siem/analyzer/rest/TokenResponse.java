package com.siem.analyzer.rest;

import com.siem.analyzer.service.AuthService;

/**
 * A token pair as the API returns it.
 *
 * <p>Field names follow RFC 6749's token response, so a generic OAuth client library can read it
 * without translation, even though this endpoint is not an OAuth authorisation server.
 */
public record TokenResponse(
        String accessToken, String refreshToken, String tokenType, long expiresIn) {

    private static final String BEARER = "Bearer";

    public static TokenResponse from(AuthService.Tokens tokens) {
        return new TokenResponse(
                tokens.accessToken(), tokens.refreshToken(), BEARER, tokens.expiresInSeconds());
    }
}
