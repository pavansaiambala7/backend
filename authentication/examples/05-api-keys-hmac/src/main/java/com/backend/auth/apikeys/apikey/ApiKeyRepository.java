package com.backend.auth.apikeys.apikey;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** SQL access to {@code api_key} (see schema.sql). Timestamps travel as UTC {@link OffsetDateTime}, the JDBC 4.2 mapping. */
@Repository
public class ApiKeyRepository {

    private static final String COLUMNS =
            "id, owner, name, prefix, key_hash, scopes, created_at, expires_at, revoked_at, last_used_at, rotated_to";

    private final JdbcClient jdbc;

    ApiKeyRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    void insert(ApiKey key) {
        jdbc.sql("""
                INSERT INTO api_key (id, owner, name, prefix, key_hash, scopes, created_at, expires_at)
                VALUES (:id, :owner, :name, :prefix, :keyHash, :scopes, :createdAt, :expiresAt)
                """)
                .param("id", key.id())
                .param("owner", key.owner())
                .param("name", key.name())
                .param("prefix", key.prefix())
                .param("keyHash", key.keyHash())
                .param("scopes", String.join(" ", new TreeSet<>(key.scopes())))
                .param("createdAt", utc(key.createdAt()))
                .param("expiresAt", utc(key.expiresAt()))
                .update();
    }

    /** Candidates for a presented key. The prefix is not unique by constraint, but a collision is astronomically rare. */
    List<ApiKey> findByPrefix(String prefix) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM api_key WHERE prefix = :prefix")
                .param("prefix", prefix)
                .query(ApiKeyRepository::map)
                .list();
    }

    Optional<ApiKey> findByIdAndOwner(UUID id, String owner) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM api_key WHERE id = :id AND owner = :owner")
                .param("id", id)
                .param("owner", owner)
                .query(ApiKeyRepository::map)
                .optional();
    }

    List<ApiKey> findByOwner(String owner) {
        return jdbc.sql("SELECT " + COLUMNS + " FROM api_key WHERE owner = :owner ORDER BY created_at DESC, id")
                .param("owner", owner)
                .query(ApiKeyRepository::map)
                .list();
    }

    /** @return false if the key was already revoked (or does not exist) */
    boolean revoke(UUID id, String owner, Instant now) {
        return jdbc.sql("UPDATE api_key SET revoked_at = :now WHERE id = :id AND owner = :owner AND revoked_at IS NULL")
                .param("now", utc(now))
                .param("id", id)
                .param("owner", owner)
                .update() == 1;
    }

    /**
     * Links the old key to its successor and shortens its life to the overlap. The {@code rotated_to IS NULL}
     * condition makes concurrent rotations of the same key fail instead of creating two successors.
     *
     * @return false if another request rotated or revoked the key first
     */
    boolean markRotated(UUID id, String owner, UUID successor, Instant newExpiry) {
        return jdbc.sql("""
                UPDATE api_key SET rotated_to = :successor, expires_at = :newExpiry
                WHERE id = :id AND owner = :owner AND rotated_to IS NULL AND revoked_at IS NULL
                """)
                .param("successor", successor)
                .param("newExpiry", utc(newExpiry))
                .param("id", id)
                .param("owner", owner)
                .update() == 1;
    }

    /** Never moves {@code last_used_at} backwards, even when concurrent requests race. */
    void recordUse(UUID id, Instant now, Instant onlyIfLastUsedBefore) {
        jdbc.sql("""
                UPDATE api_key SET last_used_at = :now
                WHERE id = :id AND (last_used_at IS NULL OR last_used_at < :threshold)
                """)
                .param("now", utc(now))
                .param("id", id)
                .param("threshold", utc(onlyIfLastUsedBefore))
                .update();
    }

    private static ApiKey map(ResultSet rs, int rowNum) throws SQLException {
        return new ApiKey(
                rs.getObject("id", UUID.class),
                rs.getString("owner"),
                rs.getString("name"),
                rs.getString("prefix"),
                rs.getBytes("key_hash"),
                parseScopes(rs.getString("scopes")),
                instant(rs, "created_at"),
                instant(rs, "expires_at"),
                instant(rs, "revoked_at"),
                instant(rs, "last_used_at"),
                rs.getObject("rotated_to", UUID.class));
    }

    private static Set<String> parseScopes(String scopes) {
        return new TreeSet<>(Arrays.asList(scopes.split(" ")));
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private static OffsetDateTime utc(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
