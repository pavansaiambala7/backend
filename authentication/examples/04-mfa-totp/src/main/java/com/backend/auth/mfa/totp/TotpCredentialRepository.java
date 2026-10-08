package com.backend.auth.mfa.totp;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class TotpCredentialRepository {

    private final JdbcClient jdbc;

    public TotpCredentialRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public Optional<TotpCredential> findByUsername(String username) {
        return jdbc.sql("""
                        select username, encrypted_secret, confirmed_at, last_used_time_step
                          from totp_credential
                         where username = :username""")
                .param("username", username)
                .query(TotpCredentialRepository::toCredential)
                .optional();
    }

    public boolean isActive(String username) {
        return jdbc.sql("select count(*) from totp_credential where username = :username and confirmed_at is not null")
                .param("username", username)
                .query(Long.class)
                .single() > 0;
    }

    /**
     * Stores a new unconfirmed secret, replacing any earlier unconfirmed one. An active credential is never
     * replaced here: the insert would violate the primary key.
     */
    public void savePending(String username, String encryptedSecret, Instant now) {
        jdbc.sql("delete from totp_credential where username = :username and confirmed_at is null")
                .param("username", username)
                .update();
        jdbc.sql("""
                        insert into totp_credential (username, encrypted_secret, created_at)
                        values (:username, :secret, :now)""")
                .param("username", username)
                .param("secret", encryptedSecret)
                .param("now", utc(now))
                .update();
    }

    /**
     * Marks a pending credential active and records the confirming code's time step, so that code cannot also be
     * used to log in.
     *
     * @return false if there was no pending credential (for example a concurrent confirmation won)
     */
    public boolean activate(String username, long timeStep, Instant now) {
        return jdbc.sql("""
                        update totp_credential
                           set confirmed_at = :now, last_used_time_step = :step
                         where username = :username and confirmed_at is null""")
                .param("now", utc(now))
                .param("step", timeStep)
                .param("username", username)
                .update() == 1;
    }

    /**
     * Records an accepted login code's time step, but only if it is later than the last one accepted.
     *
     * <p>This conditional update is the replay check that matters: it is atomic, so if the same code arrives in
     * two concurrent requests, exactly one of them updates the row.
     *
     * @return false if this step (or a later one) was already used
     */
    public boolean recordUse(String username, long timeStep) {
        return jdbc.sql("""
                        update totp_credential
                           set last_used_time_step = :step
                         where username = :username
                           and confirmed_at is not null
                           and last_used_time_step < :step""")
                .param("step", timeStep)
                .param("username", username)
                .update() == 1;
    }

    private static TotpCredential toCredential(ResultSet rs, int row) throws SQLException {
        OffsetDateTime confirmedAt = rs.getObject("confirmed_at", OffsetDateTime.class);
        return new TotpCredential(
                rs.getString("username"),
                rs.getString("encrypted_secret"),
                confirmedAt == null ? null : confirmedAt.toInstant(),
                rs.getObject("last_used_time_step", Long.class));
    }

    private static OffsetDateTime utc(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
