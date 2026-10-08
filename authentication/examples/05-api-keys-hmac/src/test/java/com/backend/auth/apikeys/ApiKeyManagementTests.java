package com.backend.auth.apikeys;

import static com.backend.auth.apikeys.AdminApi.acmeAdmin;
import static com.backend.auth.apikeys.AdminApi.createKey;
import static com.backend.auth.apikeys.AdminApi.globexAdmin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.apikeys.AdminApi.CreatedKey;
import com.backend.auth.apikeys.apikey.ApiKeyHasher;
import com.jayway.jsonpath.JsonPath;

/** The admin side: show once, store a hash, rotate with overlap, revoke, stay inside your own account. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class ApiKeyManagementTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    MutableClock clock;

    @Autowired
    JdbcClient jdbc;

    @Autowired
    ApiKeyHasher hasher;

    @Test
    void fullKeyIsReturnedOnlyByTheCreateResponse() throws Exception {
        String created = mvc.perform(post("/admin/api-keys").with(acmeAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"CI deploy key\",\"scopes\":[\"orders:read\"]}"))
                .andExpect(status().isCreated())
                .andExpect(header().string(HttpHeaders.LOCATION, matchesPattern("/admin/api-keys/[0-9a-f-]{36}")))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(jsonPath("$.key", matchesPattern("ak_live_[0-9A-Za-z]{49}")))
                .andExpect(jsonPath("$.expiresAt").value(clock.instant().plus(Duration.ofDays(90)).toString()))
                .andReturn().getResponse().getContentAsString();
        String key = JsonPath.read(created, "$.key");
        String id = JsonPath.read(created, "$.id");

        String detail = mvc.perform(get("/admin/api-keys/{id}", id).with(acmeAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.prefix").value(key.substring(0, 16)))
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andReturn().getResponse().getContentAsString();
        String list = mvc.perform(get("/admin/api-keys").with(acmeAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(detail).doesNotContain(key).doesNotContain("hash");
        assertThat(list).doesNotContain(key).doesNotContain("hash").contains(id);
    }

    @Test
    void databaseHoldsOnlyThePrefixAndAPepperedHash() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        Map<String, Object> row = jdbc.sql("SELECT * FROM api_key WHERE id = :id")
                .param("id", UUID.fromString(key.id()))
                .query().singleRow();
        byte[] storedHash = (byte[]) row.get("KEY_HASH");

        assertThat(row.get("PREFIX")).isEqualTo(key.key().substring(0, 16));
        assertThat(storedHash).isEqualTo(hasher.hash(key.key()));
        // Not a plain SHA-256: without the pepper, a stolen table cannot even be used to test candidate keys.
        assertThat(storedHash).isNotEqualTo(MessageDigest.getInstance("SHA-256").digest(key.key().getBytes(StandardCharsets.US_ASCII)));
        String secretPart = key.key().substring(16);
        assertThat(row.values()).allSatisfy(value -> assertThat(String.valueOf(value)).doesNotContain(secretPart));
    }

    @Test
    void adminEndpointsNeedAdministratorCredentials() throws Exception {
        mvc.perform(get("/admin/api-keys"))
                .andExpect(status().isUnauthorized())
                // No Basic challenge, so browsers never cache admin credentials (see SecurityConfig).
                .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
        mvc.perform(get("/admin/api-keys").with(httpBasic("acme-admin", "wrong-passphrase")))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/api-keys").with(httpBasic("nobody", "acme-admin-demo-passphrase")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidCreateRequestsAreRejected() throws Exception {
        String[] invalidBodies = {
            "{\"name\":\"k\",\"scopes\":[\"orders:delete\"]}",                      // not in the scope catalog
            "{\"name\":\"k\",\"scopes\":[\"admin\"]}",
            "{\"name\":\"k\",\"scopes\":[]}",                                       // least privilege needs a choice
            "{\"name\":\"k\",\"scopes\":[\"orders:read\"],\"expiresInDays\":366}",  // above the 365-day maximum
            "{\"name\":\"k\",\"scopes\":[\"orders:read\"],\"expiresInDays\":0}",
            "{\"scopes\":[\"orders:read\"]}"                                         // every key needs a name
        };
        for (String body : invalidBodies) {
            mvc.perform(post("/admin/api-keys").with(acmeAdmin()).contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest());
        }
    }

    @Test
    void rotationKeepsTheOldKeyWorkingOnlyDuringTheOverlap() throws Exception {
        CreatedKey old = createKey(mvc, "orders:read");
        Instant rotatedAt = clock.instant();

        String rotation = mvc.perform(post("/admin/api-keys/{id}/rotate", old.id()).with(acmeAdmin()))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.replacement.key", matchesPattern("ak_live_[0-9A-Za-z]{49}")))
                .andExpect(jsonPath("$.replacement.scopes[0]").value("orders:read"))
                .andExpect(jsonPath("$.previous.id").value(old.id()))
                .andExpect(jsonPath("$.previous.status").value("ACTIVE"))
                .andExpect(jsonPath("$.previous.expiresAt").value(rotatedAt.plus(Duration.ofHours(24)).toString()))
                .andReturn().getResponse().getContentAsString();
        String newKey = JsonPath.read(rotation, "$.replacement.key");
        assertThat((String) JsonPath.read(rotation, "$.previous.rotatedTo")).isEqualTo(JsonPath.read(rotation, "$.replacement.id"));

        // Overlap: both keys work while the client deploys the new one.
        mvc.perform(get("/v1/orders").header("X-API-Key", old.key())).andExpect(status().isOk());
        mvc.perform(get("/v1/orders").header("X-API-Key", newKey)).andExpect(status().isOk());

        clock.advance(Duration.ofHours(24));

        mvc.perform(get("/v1/orders").header("X-API-Key", old.key())).andExpect(status().isUnauthorized());
        mvc.perform(get("/v1/orders").header("X-API-Key", newKey)).andExpect(status().isOk());
    }

    @Test
    void aKeyCanBeRotatedOnlyOnce() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        mvc.perform(post("/admin/api-keys/{id}/rotate", key.id()).with(acmeAdmin())).andExpect(status().isCreated());
        // Otherwise one leaked key could keep minting successors.
        mvc.perform(post("/admin/api-keys/{id}/rotate", key.id()).with(acmeAdmin())).andExpect(status().isConflict());
    }

    @Test
    void revokedKeysCannotBeRotated() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");
        mvc.perform(post("/admin/api-keys/{id}/revoke", key.id()).with(acmeAdmin())).andExpect(status().isOk());

        mvc.perform(post("/admin/api-keys/{id}/rotate", key.id()).with(acmeAdmin())).andExpect(status().isConflict());
    }

    @Test
    void revokingTwiceKeepsTheFirstRevocation() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");
        String first = mvc.perform(post("/admin/api-keys/{id}/revoke", key.id()).with(acmeAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        clock.advance(Duration.ofMinutes(1));

        mvc.perform(post("/admin/api-keys/{id}/revoke", key.id()).with(acmeAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"))
                .andExpect(jsonPath("$.revokedAt").value((String) JsonPath.read(first, "$.revokedAt")));
    }

    @Test
    void administratorsOnlySeeTheirOwnAccountsKeys() throws Exception {
        CreatedKey acmeKey = createKey(mvc, "orders:read");

        // 404, not 403: another account cannot even learn that the id exists.
        mvc.perform(get("/admin/api-keys/{id}", acmeKey.id()).with(globexAdmin())).andExpect(status().isNotFound());
        mvc.perform(post("/admin/api-keys/{id}/revoke", acmeKey.id()).with(globexAdmin())).andExpect(status().isNotFound());
        mvc.perform(post("/admin/api-keys/{id}/rotate", acmeKey.id()).with(globexAdmin())).andExpect(status().isNotFound());
        mvc.perform(get("/admin/api-keys").with(globexAdmin()))
                .andExpect(jsonPath("$[*].id", not(hasItem(acmeKey.id()))));

        mvc.perform(get("/v1/orders").header("X-API-Key", acmeKey.key())).andExpect(status().isOk());
    }
}
