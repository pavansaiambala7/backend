package com.backend.auth.jwt.web;

import com.backend.auth.jwt.token.AccessToken;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Body of a successful login or refresh, shaped like an OAuth 2 token response (RFC 6749 section 5.1).
 * The refresh token is deliberately absent: it travels only in the HttpOnly cookie, out of reach of
 * JavaScript. The SPA keeps the access token in memory, never in localStorage.
 */
record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("scope") String scope) {

    static TokenResponse from(AccessToken token) {
        return new TokenResponse(token.value(), "Bearer", token.expiresInSeconds(), token.scope());
    }
}
