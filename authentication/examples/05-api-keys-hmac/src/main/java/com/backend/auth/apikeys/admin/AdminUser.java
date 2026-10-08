package com.backend.auth.apikeys.admin;

import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

/** An authenticated administrator, and the account whose keys they may manage. */
public class AdminUser extends User {

    public static final String ROLE = "API_KEY_ADMIN";

    private final String owner;

    AdminUser(String username, String passwordHash, String owner) {
        super(username, passwordHash, List.of(new SimpleGrantedAuthority("ROLE_" + ROLE)));
        this.owner = owner;
    }

    public String owner() {
        return owner;
    }
}
