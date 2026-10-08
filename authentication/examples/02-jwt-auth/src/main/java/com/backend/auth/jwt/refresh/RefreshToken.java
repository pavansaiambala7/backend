package com.backend.auth.jwt.refresh;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.springframework.data.domain.Persistable;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PostPersist;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;

/** One refresh token in a family (chain). Only the SHA-256 hash of the token value is stored. */
@Entity
@Table(name = "refresh_token")
public class RefreshToken implements Persistable<UUID> {

    @Id
    private UUID id;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(nullable = false, length = 100)
    private String subject;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "parent_id")
    private UUID parentId;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    /** End of the whole family; successors inherit it, so rotating forever cannot extend a login. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "revoke_reason", length = 32)
    private RevocationReason revokeReason;

    /** Ids are assigned here, so tell Spring Data whether to INSERT (persist) or merge. */
    @Transient
    private boolean isNew;

    protected RefreshToken() {
        // for JPA
    }

    private RefreshToken(UUID familyId, String subject, String tokenHash, UUID parentId,
                         Instant issuedAt, Instant expiresAt) {
        this.id = UUID.randomUUID();
        this.isNew = true;
        this.familyId = familyId;
        this.subject = subject;
        this.tokenHash = tokenHash;
        this.parentId = parentId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    /** First token of a new family, created at login. */
    static RefreshToken startFamily(String subject, String tokenHash, Instant now, Duration absoluteLifetime) {
        return new RefreshToken(UUID.randomUUID(), subject, tokenHash, null, now, now.plus(absoluteLifetime));
    }

    /** The token that replaces this one on rotation: same family, same absolute expiry. */
    RefreshToken successor(String tokenHash, Instant now) {
        return new RefreshToken(familyId, subject, tokenHash, id, now, expiresAt);
    }

    /** When this token stops working: idle timeout or end of family, whichever comes first. */
    Instant effectiveExpiry(Duration idleTimeout) {
        Instant idleExpiry = issuedAt.plus(idleTimeout);
        return idleExpiry.isBefore(expiresAt) ? idleExpiry : expiresAt;
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return isNew;
    }

    @PostLoad
    @PostPersist
    void markNotNew() {
        this.isNew = false;
    }

    public UUID getFamilyId() {
        return familyId;
    }

    public String getSubject() {
        return subject;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public UUID getParentId() {
        return parentId;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public RevocationReason getRevokeReason() {
        return revokeReason;
    }
}
