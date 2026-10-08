package com.backend.auth.apikeys;

import static com.backend.auth.apikeys.AdminApi.bearer;
import static com.backend.auth.apikeys.AdminApi.createKey;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.apikeys.AdminApi.CreatedKey;
import com.backend.auth.apikeys.apikey.ApiKeyFormat;

/** The request path: how a key is presented, verified, and turned into scopes. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfig.class)
class ApiKeyAuthenticationTests {

    private static final String INVALID_KEY_DETAIL = "The API key is invalid, expired or revoked.";

    @Autowired
    MockMvc mvc;

    @Autowired
    MutableClock clock;

    @Autowired
    ApiKeyFormat format;

    @Test
    void newKeyWorksInTheAuthorizationHeaderWithoutCreatingASession() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        mvc.perform(get("/v1/orders").header(HttpHeaders.AUTHORIZATION, bearer(key.key())))
                .andExpect(status().isOk())
                // Stateless: the key is checked on every request, nothing is remembered between them.
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test
    void newKeyWorksInTheXApiKeyHeader() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        mvc.perform(get("/v1/orders").header("X-API-Key", key.key()))
                .andExpect(status().isOk());
    }

    @Test
    void requestWithoutAKeyGets401WithABearerChallenge() throws Exception {
        mvc.perform(get("/v1/orders"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"api\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    void wellFormedButUnknownKeyIs401() throws Exception {
        String neverIssued = format.generate();   // right prefix, right checksum, but not in the database

        expectInvalidKey(mvc.perform(get("/v1/orders").header(HttpHeaders.AUTHORIZATION, bearer(neverIssued))));
    }

    @Test
    void malformedAndMistypedKeysGetTheSameAnswerAsUnknownKeys() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");
        String valid = key.key();
        char last = valid.charAt(valid.length() - 1);
        List<String> wrongKeys = List.of(
                "not-an-api-key",
                valid.substring(0, valid.length() - 1) + (last == 'a' ? 'b' : 'a'),   // typo: checksum fails
                valid.replace("ak_live_", "ak_test_"),                                // other environment
                valid + "x");                                                          // wrong length

        for (String wrong : wrongKeys) {
            expectInvalidKey(mvc.perform(get("/v1/orders").header(HttpHeaders.AUTHORIZATION, bearer(wrong))));
        }
    }

    @Test
    void revokedKeyIs401Immediately() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");
        mvc.perform(get("/v1/orders").header("X-API-Key", key.key())).andExpect(status().isOk());

        mvc.perform(post("/admin/api-keys/{id}/revoke", key.id()).with(AdminApi.acmeAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));

        expectInvalidKey(mvc.perform(get("/v1/orders").header("X-API-Key", key.key())));
    }

    @Test
    void expiredKeyIs401() throws Exception {
        CreatedKey key = createKey(mvc, AdminApi.acmeAdmin(), 1, "orders:read");
        mvc.perform(get("/v1/orders").header("X-API-Key", key.key())).andExpect(status().isOk());

        clock.advance(Duration.ofDays(1));

        expectInvalidKey(mvc.perform(get("/v1/orders").header("X-API-Key", key.key())));
    }

    @Test
    void keyInTheQueryStringIsIgnored() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        for (String parameter : List.of("api_key", "apiKey", "access_token", "key")) {
            mvc.perform(get("/v1/orders").queryParam(parameter, key.key()))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"api\""))
                    .andExpect(jsonPath("$.detail", containsString("Credentials in the URL are ignored")));
        }
    }

    @Test
    void missingScopeIs403() throws Exception {
        CreatedKey readOnly = createKey(mvc, "orders:read");

        mvc.perform(post("/v1/orders").header("X-API-Key", readOnly.key())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"keyboard\",\"quantity\":1}"))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"insufficient_scope\"")))
                .andExpect(jsonPath("$.title").value("Insufficient scope"));
    }

    @Test
    void writeScopeAllowsCreatingButNotReading() throws Exception {
        CreatedKey writeOnly = createKey(mvc, "orders:write");

        mvc.perform(post("/v1/orders").header("X-API-Key", writeOnly.key())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"keyboard\",\"quantity\":1}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.owner").value("acme"));
        mvc.perform(get("/v1/orders").header("X-API-Key", writeOnly.key()))
                .andExpect(status().isForbidden());
    }

    @Test
    void ordersBelongToTheKeysOwner() throws Exception {
        CreatedKey acme = createKey(mvc, "orders:read", "orders:write");
        CreatedKey globex = createKey(mvc, AdminApi.globexAdmin(), null, "orders:read");

        mvc.perform(post("/v1/orders").header("X-API-Key", acme.key())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"acme-only-anvil\",\"quantity\":1}"))
                .andExpect(status().isCreated());

        mvc.perform(get("/v1/orders").header("X-API-Key", acme.key()))
                .andExpect(jsonPath("$[*].item", hasItem("acme-only-anvil")));
        mvc.perform(get("/v1/orders").header("X-API-Key", globex.key()))
                .andExpect(jsonPath("$[*].item", not(hasItem("acme-only-anvil"))));
    }

    @Test
    void scopesBecomeScopeAuthorities() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");

        mvc.perform(get("/v1/me").header(HttpHeaders.AUTHORIZATION, bearer(key.key())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.owner").value("acme"))
                .andExpect(jsonPath("$.keyId").value(key.id()))
                .andExpect(jsonPath("$.keyPrefix").value(key.prefix()))
                .andExpect(jsonPath("$.authorities", hasItem("SCOPE_orders:read")))
                .andExpect(jsonPath("$.authorities", not(hasItem("SCOPE_orders:write"))));
    }

    @Test
    void sendingTwoKeysIsABadRequest() throws Exception {
        CreatedKey first = createKey(mvc, "orders:read");
        CreatedKey second = createKey(mvc, "orders:read");

        mvc.perform(get("/v1/orders")
                        .header(HttpHeaders.AUTHORIZATION, bearer(first.key()))
                        .header("X-API-Key", second.key()))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_request\"")));
    }

    @Test
    void apiKeysCannotManageApiKeys() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read", "orders:write");

        mvc.perform(get("/admin/api-keys").header(HttpHeaders.AUTHORIZATION, bearer(key.key())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void endpointsNotExplicitlyAllowedAreDenied() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read", "orders:write");

        mvc.perform(get("/v1/internal").header("X-API-Key", key.key())).andExpect(status().isForbidden());
        mvc.perform(get("/v1/internal")).andExpect(status().isUnauthorized());
    }

    @Test
    void lastUsedIsRecorded() throws Exception {
        CreatedKey key = createKey(mvc, "orders:read");
        mvc.perform(get("/admin/api-keys/{id}", key.id()).with(AdminApi.acmeAdmin()))
                .andExpect(jsonPath("$.lastUsedAt").value(nullValue()));

        mvc.perform(get("/v1/orders").header("X-API-Key", key.key())).andExpect(status().isOk());

        mvc.perform(get("/admin/api-keys/{id}", key.id()).with(AdminApi.acmeAdmin()))
                .andExpect(jsonPath("$.lastUsedAt").value(notNullValue()));
    }

    private static void expectInvalidKey(ResultActions result) throws Exception {
        result.andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"api\", error=\"invalid_token\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.title").value("Invalid API key"))
                .andExpect(jsonPath("$.detail").value(INVALID_KEY_DETAIL));
    }
}
