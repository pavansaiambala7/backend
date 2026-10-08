package com.backend.auth.authserver.user;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Looks up profile claims by username. */
public final class UserProfiles {

    private final Map<String, UserProfile> byUsername;

    UserProfiles(Collection<UserProfile> profiles) {
        this.byUsername = profiles.stream().collect(Collectors.toUnmodifiableMap(UserProfile::username, Function.identity()));
    }

    public Optional<UserProfile> find(String username) {
        return Optional.ofNullable(byUsername.get(username));
    }
}
