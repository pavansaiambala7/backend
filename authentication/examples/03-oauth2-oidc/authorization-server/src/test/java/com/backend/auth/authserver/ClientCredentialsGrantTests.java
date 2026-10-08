package com.backend.auth.authserver;

import static com.backend.auth.authserver.OAuthTestSupport.BFF_CLIENT_ID;
import static com.backend.auth.authserver.OAuthTestSupport.BFF_CLIENT_SECRET;
import static com.backend.auth.authserver.OAuthTestSupport.ISSUER;
import static com.backend.auth.authserver.OAuthTestSupport.SERVICE_CLIENT_ID;
import static com.backend.auth.authserver.OAuthTestSupport.SERVICE_CLIENT_SECRET;
import static com.backend.auth.authserver.OAuthTestSupport.clientSecretBasic;
import static com.backend.auth.authserver.OAuthTestSupport.json;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class ClientCredentialsGrantTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtDecoder jwtDecoder;

    @Test
    void serviceClientGetsAShortLivedAccessTokenForTheOrdersApi() throws Exception {
        MvcResult result = mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "orders.read"))
                .andExpect(status().isOk())
                // Token responses must never be cached by browsers or proxies (RFC 6749 section 5.1).
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                // 600 s, give or take the second that passes between issuing and answering.
                .andExpect(jsonPath("$.expires_in", allOf(greaterThan(590), lessThanOrEqualTo(600))))
                .andExpect(jsonPath("$.scope").value("orders.read"))
                // No user, so no ID token; and a client that can authenticate itself needs no refresh token.
                .andExpect(jsonPath("$.id_token").doesNotExist())
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andReturn();

        Jwt accessToken = jwtDecoder.decode(json(result, "$.access_token"));
        assertThat(accessToken.getHeaders()).containsEntry("alg", "RS256").containsKey("kid");
        assertThat(accessToken.getIssuer()).hasToString(ISSUER);
        assertThat(accessToken.getSubject()).isEqualTo(SERVICE_CLIENT_ID);
        assertThat(accessToken.getAudience()).containsExactly("orders-api");
        assertThat(accessToken.getClaimAsString("client_id")).isEqualTo(SERVICE_CLIENT_ID);
        assertThat(accessToken.getClaimAsStringList("scope")).containsExactly("orders.read");
        assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt())).isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    void accessTokenIsSignedWithTheKeyPublishedInTheJwks() throws Exception {
        MvcResult tokenResult = mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "orders.read"))
                .andExpect(status().isOk())
                .andReturn();
        String tokenKeyId = (String) jwtDecoder.decode(json(tokenResult, "$.access_token")).getHeaders().get("kid");

        String jwks = mvc.perform(get("/oauth2/jwks")).andReturn().getResponse().getContentAsString();
        String publishedKeyId = JsonPath.read(jwks, "$.keys[0].kid");
        assertThat(tokenKeyId).isEqualTo(publishedKeyId);
    }

    @Test
    void wrongClientSecretIsRejected() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(SERVICE_CLIENT_ID, "not-the-secret"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "orders.read"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void scopesThatWereNotRegisteredForTheClientAreRefused() throws Exception {
        mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "orders.write"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"));
    }

    @Test
    void clientCannotUseAGrantTypeItWasNotRegisteredFor() throws Exception {
        // The BFF client is registered for authorization_code + refresh_token only.
        mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(BFF_CLIENT_ID, BFF_CLIENT_SECRET))
                        .param("grant_type", "client_credentials")
                        .param("scope", "orders.read"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unauthorized_client"));
    }

    @Test
    void deprecatedPasswordGrantIsNotSupported() throws Exception {
        // Resource owner password credentials: the client would see the user's password (RFC 9700 forbids it).
        mvc.perform(post("/oauth2/token")
                        .with(clientSecretBasic(BFF_CLIENT_ID, BFF_CLIENT_SECRET))
                        .param("grant_type", "password")
                        .param("username", "alice")
                        .param("password", "alice-demo-password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }
}
