package com.backend.auth.jwt.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Upper bounds keep absurdly large inputs away from the password hasher. */
record LoginRequest(@NotBlank @Size(max = 100) String username, @NotBlank @Size(max = 256) String password) {

    @Override
    public String toString() {
        return "LoginRequest[username=" + username + ", password=***]";   // never log a password
    }
}
