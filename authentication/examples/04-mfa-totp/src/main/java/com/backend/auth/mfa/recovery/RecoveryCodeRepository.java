package com.backend.auth.mfa.recovery;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RecoveryCodeRepository {

    /** A stored code: only its hash. */
    public record StoredRecoveryCode(long id, String codeHash) {
    }

    private final JdbcClient jdbc;

    public RecoveryCodeRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    /** Deletes the user's previous codes (used or not) and stores the new set. */
    public void replaceAll(String username, List<String> codeHashes, Instant now) {
        jdbc.sql("delete from recovery_code where username = :username")
                .param("username", username)
                .update();
        for (String hash : codeHashes) {
            jdbc.sql("insert into recovery_code (username, code_hash, created_at) values (:username, :hash, :now)")
                    .param("username", username)
                    .param("hash", hash)
                    .param("now", utc(now))
                    .update();
        }
    }

    public List<StoredRecoveryCode> findUnused(String username) {
        return jdbc.sql("select id, code_hash from recovery_code where username = :username and used_at is null order by id")
                .param("username", username)
                .query((rs, row) -> new StoredRecoveryCode(rs.getLong("id"), rs.getString("code_hash")))
                .list();
    }

    public int countUnused(String username) {
        return jdbc.sql("select count(*) from recovery_code where username = :username and used_at is null")
                .param("username", username)
                .query(Integer.class)
                .single();
    }

    /**
     * Consumes a code. Atomic: if the same code is submitted twice concurrently, only one update matches
     * {@code used_at is null}.
     *
     * @return false if the code was already used
     */
    public boolean markUsed(long id, Instant now) {
        return jdbc.sql("update recovery_code set used_at = :now where id = :id and used_at is null")
                .param("now", utc(now))
                .param("id", id)
                .update() == 1;
    }

    private static OffsetDateTime utc(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
