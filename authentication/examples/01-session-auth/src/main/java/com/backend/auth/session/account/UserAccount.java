package com.backend.auth.session.account;

import java.time.Instant;
import java.util.Locale;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "user_account")
public class UserAccount {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Normalized (trimmed, lower-case) so "Alice@Example.com" and "alice@example.com" are one account. */
    @Column(nullable = false, unique = true, length = 320)
    private String email;

    /** Self-describing hash, e.g. "{argon2}$argon2id$v=19$m=19456,t=2,p=1$...". Never the password. */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected UserAccount() {
        // for JPA
    }

    public UserAccount(String email, String passwordHash, Instant createdAt) {
        this.email = normalizeEmail(email);
        this.passwordHash = passwordHash;
        this.createdAt = createdAt;
    }

    public static String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    void changePasswordHash(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
    }
}
