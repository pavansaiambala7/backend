package com.backend.auth.authserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import com.jayway.jsonpath.JsonPath;

/** Constants matching application.yml, plus helpers that drive the real endpoints through MockMvc. */
final class OAuthTestSupport {

    static final String ISSUER = "http://localhost:9000";

    static final String BFF_CLIENT_ID = "bff-client";
    static final String BFF_CLIENT_SECRET = "bff-client-demo-secret";
    static final String BFF_REDIRECT_URI = "http://127.0.0.1:8080/login/oauth2/code/auth-server";
    static final String BFF_SCOPES = "openid profile orders.read";

    static final String SERVICE_CLIENT_ID = "service-client";
    static final String SERVICE_CLIENT_SECRET = "service-client-demo-secret";

    static final String ALICE = "alice";
    static final String ALICE_PASSWORD = "alice-demo-password";

    private static final SecureRandom RANDOM = new SecureRandom();

    private OAuthTestSupport() {
    }

    /** Logs in through the authorization server's own login form and returns the authenticated session. */
    static MockHttpSession login(MockMvc mvc, String username, String password) throws Exception {
        MvcResult result = mvc.perform(formLogin("/login").user(username).password(password))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    /** A GET /oauth2/authorize request for the BFF client with PKCE (S256), state and nonce. */
    static MockHttpServletRequestBuilder authorizationRequest(Pkce pkce, String state, String nonce) {
        return get("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", BFF_CLIENT_ID)
                .queryParam("redirect_uri", BFF_REDIRECT_URI)
                .queryParam("scope", BFF_SCOPES)
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", pkce.challenge())
                .queryParam("code_challenge_method", "S256");
    }

    /** Runs the front-channel part of the flow and returns the query parameters of the callback. */
    static MultiValueMap<String, String> authorize(MockMvc mvc, MockHttpSession session, Pkce pkce, String state, String nonce)
            throws Exception {
        String location = mvc.perform(authorizationRequest(pkce, state, nonce).session(session))
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();
        assertThat(location).startsWith(BFF_REDIRECT_URI + "?");
        return queryParams(location);
    }

    /** The token request the BFF sends from its back channel to redeem a code. */
    static MockHttpServletRequestBuilder codeExchange(String code, String codeVerifier) {
        return post("/oauth2/token")
                .with(clientSecretBasic(BFF_CLIENT_ID, BFF_CLIENT_SECRET))
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", BFF_REDIRECT_URI)
                .param("code_verifier", codeVerifier);
    }

    static MockHttpServletRequestBuilder refresh(String refreshToken) {
        return post("/oauth2/token")
                .with(clientSecretBasic(BFF_CLIENT_ID, BFF_CLIENT_SECRET))
                .param("grant_type", "refresh_token")
                .param("refresh_token", refreshToken);
    }

    static RequestPostProcessor clientSecretBasic(String clientId, String secret) {
        return request -> {
            String credentials = clientId + ":" + secret;
            request.addHeader(HttpHeaders.AUTHORIZATION,
                    "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
            return request;
        };
    }

    static MultiValueMap<String, String> queryParams(String location) {
        return UriComponentsBuilder.fromUriString(location).build().getQueryParams();
    }

    static String json(MvcResult result, String path) throws Exception {
        return JsonPath.read(result.getResponse().getContentAsString(), path);
    }

    static String randomValue() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** RFC 7636: a high-entropy verifier and its S256 challenge. */
    record Pkce(String verifier, String challenge) {

        static Pkce generate() {
            byte[] bytes = new byte[32];
            RANDOM.nextBytes(bytes);
            String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            return new Pkce(verifier, s256(verifier));
        }

        private static String s256(String verifier) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            }
            catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }
}
