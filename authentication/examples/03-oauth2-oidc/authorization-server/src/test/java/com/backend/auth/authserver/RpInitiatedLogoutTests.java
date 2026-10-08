package com.backend.auth.authserver;

import static com.backend.auth.authserver.OAuthTestSupport.ALICE;
import static com.backend.auth.authserver.OAuthTestSupport.ALICE_PASSWORD;
import static com.backend.auth.authserver.OAuthTestSupport.authorize;
import static com.backend.auth.authserver.OAuthTestSupport.codeExchange;
import static com.backend.auth.authserver.OAuthTestSupport.json;
import static com.backend.auth.authserver.OAuthTestSupport.login;
import static com.backend.auth.authserver.OAuthTestSupport.randomValue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.authserver.OAuthTestSupport.Pkce;

/** OpenID Connect RP-Initiated Logout 1.0 at /connect/logout. */
@SpringBootTest
@AutoConfigureMockMvc
class RpInitiatedLogoutTests {

    private static final String REGISTERED_POST_LOGOUT_URI = "http://127.0.0.1:8080/logged-out";

    @Autowired
    MockMvc mvc;

    MockHttpSession aliceSession;
    String idToken;

    @BeforeEach
    void signInAlice() throws Exception {
        aliceSession = login(mvc, ALICE, ALICE_PASSWORD);
        Pkce pkce = Pkce.generate();
        String code = authorize(mvc, aliceSession, pkce, randomValue(), randomValue()).getFirst("code");
        idToken = json(mvc.perform(codeExchange(code, pkce.verifier())).andReturn(), "$.id_token");
    }

    @Test
    void logoutEndsTheAuthorizationServerSessionAndReturnsToTheRegisteredUri() throws Exception {
        String state = randomValue();

        mvc.perform(get("/connect/logout")
                        .session(aliceSession)
                        .queryParam("id_token_hint", idToken)
                        .queryParam("post_logout_redirect_uri", REGISTERED_POST_LOGOUT_URI)
                        .queryParam("state", state))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(REGISTERED_POST_LOGOUT_URI + "?state=" + state));

        // Without this, the next "Sign in" at the client would log the user straight back in.
        assertThat(aliceSession.isInvalid()).isTrue();
    }

    @Test
    void unregisteredPostLogoutRedirectUriIsRefused() throws Exception {
        // Otherwise the logout endpoint would be an open redirector for phishing links.
        mvc.perform(get("/connect/logout")
                        .session(aliceSession)
                        .queryParam("id_token_hint", idToken)
                        .queryParam("post_logout_redirect_uri", "https://attacker.example/"))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist(HttpHeaders.LOCATION));

        assertThat(aliceSession.isInvalid()).isFalse();
    }
}
