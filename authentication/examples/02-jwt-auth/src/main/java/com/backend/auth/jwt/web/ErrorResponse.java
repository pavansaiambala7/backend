package com.backend.auth.jwt.web;

import com.fasterxml.jackson.annotation.JsonProperty;

record ErrorResponse(
        @JsonProperty("error") String error,
        @JsonProperty("error_description") String description) {

    /** One message for unknown user and wrong password, so the endpoint does not reveal which accounts exist. */
    static final ErrorResponse INVALID_CREDENTIALS =
            new ErrorResponse("invalid_credentials", "Invalid username or password");

    /** One message for missing, unknown, expired, revoked and reused tokens; the reason is only logged. */
    static final ErrorResponse INVALID_REFRESH_TOKEN =
            new ErrorResponse("invalid_refresh_token", "Refresh token is missing, expired or revoked; log in again");
}
