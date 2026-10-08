package com.backend.auth.clientapp;

import static com.backend.auth.clientapp.BffTestSupport.queryParams;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class LoginRedirectTests {

    private static final String AUTHORIZATION_ENDPOINT = "http://localhost:9000/oauth2/authorize";

    @Autowired
    MockMvc mvc;

    @Test
    void unauthenticatedPageRequestStartsTheOidcLogin() throws Exception {
        mvc.perform(get("/").accept(MediaType.TEXT_HTML))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/oauth2/authorization/auth-server"));
    }

    @Test
    void loginRedirectsToTheAuthorizationEndpointWithPkceStateAndNonce() throws Exception {
        MvcResult result = mvc.perform(get("/oauth2/authorization/auth-server"))
                .andExpect(status().isFound())
                .andReturn();
        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith(AUTHORIZATION_ENDPOINT + "?");

        Map<String, String> params = queryParams(location);
        assertThat(params)
                .containsEntry("response_type", "code")
                .containsEntry("client_id", "bff-client")
                .containsEntry("scope", "openid profile orders.read")
                .containsEntry("redirect_uri", "http://localhost/login/oauth2/code/auth-server")
                .containsEntry("code_challenge_method", "S256");
        // state: CSRF protection for the callback. nonce: binds the ID token to this login attempt.
        // code_challenge: SHA-256 of a verifier that never leaves this server (43 base64url characters).
        assertThat(params.get("state")).isNotBlank();
        assertThat(params.get("nonce")).isNotBlank();
        assertThat(params.get("code_challenge")).hasSize(43);
        // The secret halves (verifier, expected state and nonce) are kept in the server-side session.
        assertThat(result.getRequest().getSession(false)).isNotNull();
    }

    @Test
    void everyLoginAttemptGetsFreshStateNonceAndPkce() throws Exception {
        Map<String, String> first = queryParams(startLogin(new MockHttpSession()));
        Map<String, String> second = queryParams(startLogin(new MockHttpSession()));

        assertThat(second.get("state")).isNotEqualTo(first.get("state"));
        assertThat(second.get("nonce")).isNotEqualTo(first.get("nonce"));
        assertThat(second.get("code_challenge")).isNotEqualTo(first.get("code_challenge"));
    }

    @Test
    void callbackWithAStateThisSessionDidNotCreateIsRejected() throws Exception {
        MockHttpSession session = new MockHttpSession();
        startLogin(session);

        // An attacker's own code delivered to the victim's browser (login CSRF / code injection).
        MvcResult result = mvc.perform(get("/login/oauth2/code/auth-server")
                        .session(session)
                        .param("code", "attacker-code")
                        .param("state", "attacker-state"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated())
                .andReturn();

        // Rejected before any token request: there is no saved authorization request for that state.
        Object failure = result.getRequest().getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
        assertThat(failure).isInstanceOfSatisfying(OAuth2AuthenticationException.class, ex ->
                assertThat(ex.getError().getErrorCode()).isEqualTo("authorization_request_not_found"));
    }

    @Test
    void unauthenticatedApiCallGets401InsteadOfARedirect() throws Exception {
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist(HttpHeaders.LOCATION));
    }

    private String startLogin(MockHttpSession session) throws Exception {
        return mvc.perform(get("/oauth2/authorization/auth-server").session(session))
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();
    }
}
