package com.backend.auth.jwt;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import com.backend.auth.jwt.security.AuthEndpointCsrfFilter;
import com.jayway.jsonpath.JsonPath;

import jakarta.servlet.http.Cookie;

/** The login / refresh / logout calls a well-behaved first-party client makes, for MockMvc tests. */
public final class AuthFlows {

    public static final String COOKIE = "__Secure-refresh_token";
    public static final String CSRF_HEADER = AuthEndpointCsrfFilter.REQUIRED_HEADER;

    /** DEMO credentials from application.yml. alice: orders:read + orders:write; bob: orders:read. */
    public static final String ALICE_PASSWORD = "alice-demo-passphrase";
    public static final String BOB_PASSWORD = "bob-demo-passphrase";

    private AuthFlows() {
    }

    public record Tokens(String accessToken, String refreshToken) {
    }

    public static MockHttpServletRequestBuilder loginRequest(String username, String password) {
        return post("/auth/login")
                .header(CSRF_HEADER, "1")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"%s\",\"password\":\"%s\"}".formatted(username, password));
    }

    public static Tokens login(MockMvc mvc, String username, String password) throws Exception {
        MvcResult result = mvc.perform(loginRequest(username, password)).andExpect(status().isOk()).andReturn();
        return tokens(result);
    }

    public static Tokens loginAlice(MockMvc mvc) throws Exception {
        return login(mvc, "alice", ALICE_PASSWORD);
    }

    public static MockHttpServletRequestBuilder refreshRequest(String refreshToken) {
        return post("/auth/refresh").header(CSRF_HEADER, "1").cookie(new Cookie(COOKIE, refreshToken));
    }

    public static MockHttpServletRequestBuilder logoutRequest(String refreshToken) {
        return post("/auth/logout").header(CSRF_HEADER, "1").cookie(new Cookie(COOKIE, refreshToken));
    }

    /** Access token from the JSON body, refresh token from the Set-Cookie header. */
    public static Tokens tokens(MvcResult result) throws Exception {
        String accessToken = JsonPath.read(result.getResponse().getContentAsString(), "$.access_token");
        Cookie cookie = result.getResponse().getCookie(COOKIE);
        return new Tokens(accessToken, cookie == null ? null : cookie.getValue());
    }

    public static String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    /** Independent SHA-256 so the test does not trust the code under test to hash correctly. */
    public static String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
