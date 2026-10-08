package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.ALICE_PASSWORD;
import static com.backend.auth.jwt.AuthFlows.COOKIE;
import static com.backend.auth.jwt.AuthFlows.CSRF_HEADER;
import static com.backend.auth.jwt.AuthFlows.bearer;
import static com.backend.auth.jwt.AuthFlows.loginRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.backend.auth.jwt.keys.SigningKeyStore;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@SpringBootTest
@AutoConfigureMockMvc
class LoginTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    SigningKeyStore keys;

    @Test
    void loginReturnsAShortLivedRs256AccessTokenThatTheApiAccepts() throws Exception {
        MvcResult result = mvc.perform(loginRequest("alice", ALICE_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.scope").value("orders:read orders:write"))
                // The refresh token is only ever in the HttpOnly cookie, never readable by JavaScript.
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andReturn();
        String accessToken = AuthFlows.tokens(result).accessToken();

        SignedJWT jwt = TestTokens.parseUnverified(accessToken);
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(keys.activeKeyId());
        assertThat(jwt.getHeader().getType().getType()).isEqualTo("at+jwt");

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo(TestTokens.ISSUER);
        assertThat(claims.getAudience()).containsExactly(TestTokens.AUDIENCE);
        assertThat(claims.getSubject()).isEqualTo("alice");
        // Only real permissions: no FACTOR_PASSWORD or other login-time authorities leak into the token.
        assertThat(claims.getStringClaim("scope")).isEqualTo("orders:read orders:write");
        assertThat(claims.getStringClaim("client_id")).isEqualTo(TestTokens.CLIENT_ID);
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(lifetime(claims.getIssueTime(), claims.getExpirationTime())).isEqualTo(Duration.ofMinutes(15));
        assertThat(claims.getNotBeforeTime()).isEqualTo(claims.getIssueTime());

        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"))
                .andExpect(jsonPath("$.token_id").value(claims.getJWTID()));
    }

    @Test
    void loginSetsAHardenedRefreshCookieScopedToTheAuthPath() throws Exception {
        MvcResult result = mvc.perform(loginRequest("alice", ALICE_PASSWORD)).andExpect(status().isOk()).andReturn();

        String setCookie = result.getResponse().getHeader(HttpHeaders.SET_COOKIE);
        assertThat(setCookie)
                .startsWith(COOKIE + "=")
                .contains("HttpOnly", "Secure", "SameSite=Strict", "Path=/auth", "Max-Age=86400")
                .doesNotContain("Domain=");
        // 256 random bits, Base64URL without padding.
        assertThat(AuthFlows.tokens(result).refreshToken()).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void wrongPasswordAndUnknownUserGetTheSameAnswerAndNoCookie() throws Exception {
        String wrongPassword = mvc.perform(loginRequest("alice", "not-alices-password"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn().getResponse().getContentAsString();

        String unknownUser = mvc.perform(loginRequest("mallory", "whatever-password"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn().getResponse().getContentAsString();

        assertThat(unknownUser).isEqualTo(wrongPassword);
    }

    @Test
    void scopesComeFromTheUserRecord() throws Exception {
        MvcResult result = mvc.perform(loginRequest("bob", AuthFlows.BOB_PASSWORD))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scope").value("orders:read"))
                .andReturn();

        JWTClaimsSet claims = TestTokens.parseUnverified(AuthFlows.tokens(result).accessToken()).getJWTClaimsSet();
        assertThat(claims.getStringClaim("scope")).isEqualTo("orders:read");
    }

    @Test
    void loginAcceptsJsonOnly() throws Exception {
        // A cross-site HTML form can post urlencoded, multipart or text/plain bodies, never JSON.
        mvc.perform(post("/auth/login")
                        .header(CSRF_HEADER, "1")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", "alice")
                        .param("password", ALICE_PASSWORD))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void blankCredentialsAreRejectedBeforeAuthentication() throws Exception {
        mvc.perform(loginRequest("", ""))
                .andExpect(status().isBadRequest());
    }

    private static Duration lifetime(Date issuedAt, Date expiresAt) {
        return Duration.between(issuedAt.toInstant(), expiresAt.toInstant());
    }
}
