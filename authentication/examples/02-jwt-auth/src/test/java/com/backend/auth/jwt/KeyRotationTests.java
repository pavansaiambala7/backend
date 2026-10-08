package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.bearer;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.jwt.keys.InMemorySigningKeyStore;
import com.jayway.jsonpath.JsonPath;

/** Publish, activate, retire: tokens keep working through a rotation until their key is retired. */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext   // rotates the application's keys; other test classes get a fresh context
class KeyRotationTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    InMemorySigningKeyStore keys;

    @Test
    void rotationWithoutDowntime() throws Exception {
        String oldKid = keys.activeKeyId();
        String tokenSignedWithOldKey = AuthFlows.loginAlice(mvc).accessToken();

        // 1. Publish: verifiers can fetch the new key, but nothing is signed with it yet.
        String newKid = keys.publishNewKey();
        assertThat(publishedKids()).containsExactlyInAnyOrder(oldKid, newKid);
        assertThat(kidOf(AuthFlows.loginAlice(mvc).accessToken())).isEqualTo(oldKid);

        // 2. Activate: new tokens use the new kid; tokens signed with the old key still verify.
        keys.activate(newKid);
        String tokenSignedWithNewKey = AuthFlows.loginAlice(mvc).accessToken();
        assertThat(kidOf(tokenSignedWithNewKey)).isEqualTo(newKid);
        callApi(tokenSignedWithOldKey).andExpect(status().isOk());
        callApi(tokenSignedWithNewKey).andExpect(status().isOk());

        // 3. Retire (after the longest token lifetime): the old key is gone, and so are its tokens.
        keys.retire(oldKid);
        assertThat(publishedKids()).containsExactly(newKid);
        callApi(tokenSignedWithOldKey).andExpect(status().isUnauthorized());
        callApi(tokenSignedWithNewKey).andExpect(status().isOk());
    }

    private List<String> publishedKids() throws Exception {
        String body = mvc.perform(get("/.well-known/jwks.json")).andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.keys[*].kid");
    }

    private static String kidOf(String token) {
        return TestTokens.parseUnverified(token).getHeader().getKeyID();
    }

    private ResultActions callApi(String token) throws Exception {
        return mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(token)));
    }
}
