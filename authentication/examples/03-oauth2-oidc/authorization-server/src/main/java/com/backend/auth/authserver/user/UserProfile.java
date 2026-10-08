package com.backend.auth.authserver.user;

/** Profile data released to clients that were granted the {@code profile} scope. */
public record UserProfile(String username, String fullName) {
}
