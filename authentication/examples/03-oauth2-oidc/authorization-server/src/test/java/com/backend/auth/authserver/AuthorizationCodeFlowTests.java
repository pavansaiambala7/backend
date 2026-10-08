package com.backend.auth.authserver;

import static com.backend.auth.authserver.OAuthTestSupport.ALICE;
import static com.backend.auth.authserver.OAuthTestSupport.ALICE_PASSWORD;
import static com.backend.auth.authserver.OAuthTestSupport.BFF_CLIENT_ID;
import static com.backend.auth.authserver.OAuthTestSupport.BFF_CLIENT_SECRET;
import static com.backend.auth.authserver.OAuthTestSupport.BFF_REDIRECT_URI;
import static com.backend.auth.authserver.OAuthTestSupport.BFF_SCOPES;
import static com.backend.auth.authserver.OAuthTestSupport.ISSUER;
import static com.backend.auth.authserver.OAuthTestSupport.authorizationRequest;
import static com.backend.auth.authserver.OAuthTestSupport.clientSecretBasic;
import static com.backend.auth.authserver.OAuthTestSupport.codeExchange;
import static com.backend.auth.authserver.OAuthTestSupport.json;
import static com.backend.auth.authserver.OAuthTestSupport.login;
import static com.backend.auth.authserver.OAuthTestSupport.queryParams;
import static com.backend.auth.authserver.OAuthTestSupport.randomValue;
import static com.backend.auth.authserver.OAuthTestSupport.refresh;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;

import com.backend.auth.authserver.OAuthTestSupport.Pkce;

/**
 * The authorization code flow with PKCE, driven end to end through MockMvc exactly as the BFF and the
 * browser would drive it: log in, call /oauth2/authorize, receive the code on the redirect URI,
 * redeem it at /oauth2/token with the code verifier.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationCodeFlowTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    JwtDecoder jwtDecoder;

    MockHttpSession aliceSession;

    @BeforeEach
    void logInAlice() throws Exception {
        aliceSession = login(mvc, ALICE, ALICE_PASSWORD);
    }

    @Test
    void browserWithoutSessionIsSentToTheLoginPage() throws Exception {
        mvc.perform(authorizationRequest(Pkce.generate(), randomValue(), randomValue()).accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void codeFlowWithPkceIssuesAccessTokenIdTokenAndRefreshToken() throws Exception {
        Pkce pkce = Pkce.generate();
        String state = randomValue();
        String nonce = randomValue();

        // 1. Front channel: the AS redirects back to the registered URI with a code and the same state.
        MultiValueMap<String, String> callback = authorize(pkce, state, nonce);
        assertThat(callback.getFirst("state")).isEqualTo(state);
        String code = callback.getFirst("code");
        assertThat(code).isNotBlank();

        // 2. Back channel: the client authenticates and proves it started the flow (code_verifier).
        MvcResult tokenResponse = mvc.perform(codeExchange(code, pkce.verifier()))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, containsString("no-store")))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in", allOf(greaterThan(590), lessThanOrEqualTo(600))))
                .andExpect(jsonPath("$.scope").value(BFF_SCOPES))
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();

        // The ID token is the proof of authentication, addressed to the client (aud) and bound to
        // this login attempt (nonce).
        Jwt idToken = jwtDecoder.decode(json(tokenResponse, "$.id_token"));
        assertThat(idToken.getIssuer()).hasToString(ISSUER);
        assertThat(idToken.getSubject()).isEqualTo(ALICE);
        assertThat(idToken.getAudience()).containsExactly(BFF_CLIENT_ID);
        assertThat(idToken.getClaimAsString("azp")).isEqualTo(BFF_CLIENT_ID);
        assertThat(idToken.getClaimAsString("nonce")).isEqualTo(nonce);
        assertThat(idToken.getClaimAsString("name")).isEqualTo("Alice Anderson");
        assertThat(idToken.getClaims()).containsKeys("auth_time", "sid");

        // The access token is for the orders API, not for the client.
        Jwt accessToken = jwtDecoder.decode(json(tokenResponse, "$.access_token"));
        assertThat(accessToken.getSubject()).isEqualTo(ALICE);
        assertThat(accessToken.getAudience()).containsExactly("orders-api");
        assertThat(accessToken.getClaimAsString("client_id")).isEqualTo(BFF_CLIENT_ID);
        assertThat(accessToken.getClaimAsStringList("scope")).containsExactlyInAnyOrder("openid", "profile", "orders.read");
        assertThat(Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt())).isEqualTo(Duration.ofMinutes(10));

        // 3. The UserInfo endpoint returns the same subject for that access token.
        mvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value(ALICE))
                .andExpect(jsonPath("$.name").value("Alice Anderson"));
    }

    @Test
    void wrongCodeVerifierIsRejected() throws Exception {
        String code = authorize(Pkce.generate(), randomValue(), randomValue()).getFirst("code");

        // An attacker who stole or injected the code does not have the verifier from the original session.
        mvc.perform(codeExchange(code, Pkce.generate().verifier()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void authorizationRequestWithoutPkceIsRefused() throws Exception {
        String location = mvc.perform(get("/oauth2/authorize")
                        .session(aliceSession)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", BFF_CLIENT_ID)
                        .queryParam("redirect_uri", BFF_REDIRECT_URI)
                        .queryParam("scope", BFF_SCOPES)
                        .queryParam("state", randomValue()))
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        MultiValueMap<String, String> callback = queryParams(location);
        assertThat(callback.getFirst("error")).isEqualTo("invalid_request");
        assertThat(callback.getFirst("code")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://attacker.example/callback",
        "http://127.0.0.1:8080/login/oauth2/code/auth-server/extra",   // prefix match is not enough
        "http://127.0.0.1:8080/login/oauth2/code/auth-server?next=x",  // neither is a different query
        "http://localhost:8080/login/oauth2/code/auth-server"          // nor a different host for the same app
    })
    void unregisteredRedirectUriIsRejectedWithoutRedirecting(String redirectUri) throws Exception {
        mvc.perform(get("/oauth2/authorize")
                        .session(aliceSession)
                        .queryParam("response_type", "code")
                        .queryParam("client_id", BFF_CLIENT_ID)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("scope", BFF_SCOPES)
                        .queryParam("state", randomValue())
                        .queryParam("code_challenge", Pkce.generate().challenge())
                        .queryParam("code_challenge_method", "S256"))
                // An error page, never a redirect: redirecting to an unverified URI would hand the
                // code (or at least the user) to whoever controls it.
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist(HttpHeaders.LOCATION));
    }

    @Test
    void implicitFlowIsNotSupported() throws Exception {
        mvc.perform(get("/oauth2/authorize")
                        .session(aliceSession)
                        .queryParam("response_type", "token")
                        .queryParam("client_id", BFF_CLIENT_ID)
                        .queryParam("redirect_uri", BFF_REDIRECT_URI)
                        .queryParam("scope", BFF_SCOPES)
                        .queryParam("state", randomValue()))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist(HttpHeaders.LOCATION));
    }

    @Test
    void reusedAuthorizationCodeIsRejectedAndRevokesTheTokensItIssued() throws Exception {
        Pkce pkce = Pkce.generate();
        String code = authorize(pkce, randomValue(), randomValue()).getFirst("code");
        String accessToken = json(mvc.perform(codeExchange(code, pkce.verifier()))
                .andExpect(status().isOk())
                .andReturn(), "$.access_token");

        // A second redemption means the code leaked (logs, Referer, history). RFC 6749 section 4.1.2:
        // refuse it and revoke what the first redemption produced, since that may have been the attacker.
        mvc.perform(codeExchange(code, pkce.verifier()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));

        mvc.perform(post("/oauth2/introspect")
                        .with(clientSecretBasic(BFF_CLIENT_ID, BFF_CLIENT_SECRET))
                        .param("token", accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void refreshTokenIsRotatedAndTheOldOneStopsWorking() throws Exception {
        Pkce pkce = Pkce.generate();
        String code = authorize(pkce, randomValue(), randomValue()).getFirst("code");
        String firstRefreshToken = json(mvc.perform(codeExchange(code, pkce.verifier())).andReturn(), "$.refresh_token");

        MvcResult refreshed = mvc.perform(refresh(firstRefreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn();
        String secondRefreshToken = json(refreshed, "$.refresh_token");
        assertThat(secondRefreshToken).isNotBlank().isNotEqualTo(firstRefreshToken);

        mvc.perform(refresh(firstRefreshToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
        mvc.perform(refresh(secondRefreshToken))
                .andExpect(status().isOk());
    }

    private MultiValueMap<String, String> authorize(Pkce pkce, String state, String nonce) throws Exception {
        return OAuthTestSupport.authorize(mvc, aliceSession, pkce, state, nonce);
    }
}
