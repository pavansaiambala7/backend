package com.backend.auth.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.jwt.keys.SigningKeyStore;
import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class JwksTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    SigningKeyStore keys;

    @Test
    void jwksIsPublicCacheableAndListsTheKeyThatSignsTokens() throws Exception {
        String accessToken = AuthFlows.loginAlice(mvc).accessToken();
        String tokenKid = TestTokens.parseUnverified(accessToken).getHeader().getKeyID();

        String body = mvc.perform(get("/.well-known/jwks.json"))   // no Authorization header needed
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "max-age=300, public"))
                .andReturn().getResponse().getContentAsString();

        List<Map<String, Object>> jwks = JsonPath.read(body, "$.keys");
        assertThat(jwks).singleElement().satisfies(key -> {
            assertThat(key).containsEntry("kid", tokenKid)
                    .containsEntry("kty", "RSA")
                    .containsEntry("alg", "RS256")
                    .containsEntry("use", "sig")
                    .containsKeys("n", "e");
        });
    }

    @Test
    void jwksNeverContainsPrivateKeyMaterial() throws Exception {
        String body = mvc.perform(get("/.well-known/jwks.json")).andReturn().getResponse().getContentAsString();

        List<Map<String, Object>> jwks = JsonPath.read(body, "$.keys");
        assertThat(jwks).allSatisfy(key -> assertThat(key).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi", "oth"));
        // The private key exists in the store, so the stripping above really happened.
        assertThat(keys.allSigningKeys()).allSatisfy(key -> assertThat(key.isPrivate()).isTrue());
    }

    @Test
    void protectedResourceMetadataDescribesThisApiTruthfully() throws Exception {
        // RFC 9728, linked from every 401's WWW-Authenticate header by Spring Security 7.
        mvc.perform(get("/.well-known/oauth-protected-resource"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"))
                .andExpect(jsonPath("$.scopes_supported").value(containsInAnyOrder("orders:read", "orders:write")))
                .andExpect(jsonPath("$.tls_client_certificate_bound_access_tokens").value(false));
    }
}
