package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.ALICE_PASSWORD;
import static com.backend.auth.jwt.AuthFlows.COOKIE;
import static com.backend.auth.jwt.AuthFlows.refreshRequest;
import static com.backend.auth.jwt.AuthFlows.sha256Hex;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.jwt.AuthFlows.Tokens;
import com.backend.auth.jwt.refresh.RefreshTokenRepository;

import jakarta.servlet.http.Cookie;

/**
 * What a malicious page could make a logged-in victim's browser send. The cookie is attached (as if
 * SameSite had failed or the attacker were same-site), so these tests show the other layers holding.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthEndpointCsrfTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    RefreshTokenRepository repository;

    @Test
    void refreshWithoutTheCustomHeaderIsRefusedAndTheTokenIsNotConsumed() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        mvc.perform(post("/auth/refresh").cookie(new Cookie(COOKIE, login.refreshToken())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("csrf_check_failed"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));

        assertThat(repository.findByTokenHash(sha256Hex(login.refreshToken())).orElseThrow().getUsedAt()).isNull();
        mvc.perform(refreshRequest(login.refreshToken())).andExpect(status().isOk());
    }

    @Test
    void refreshFromAForeignOriginIsRefusedEvenWithTheHeader() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        mvc.perform(refreshRequest(login.refreshToken()).header(HttpHeaders.ORIGIN, "https://evil.example"))
                .andExpect(status().isForbidden());
        // Sandboxed iframes and some redirects send the opaque origin "null".
        mvc.perform(refreshRequest(login.refreshToken()).header(HttpHeaders.ORIGIN, "null"))
                .andExpect(status().isForbidden());
    }

    @Test
    void crossSiteFetchMetadataIsRefused() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        mvc.perform(refreshRequest(login.refreshToken()).header("Sec-Fetch-Site", "cross-site"))
                .andExpect(status().isForbidden());
    }

    @Test
    void ourOwnOriginIsAllowed() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        mvc.perform(refreshRequest(login.refreshToken())
                        .header(HttpHeaders.ORIGIN, "http://localhost:8082")
                        .header("Sec-Fetch-Site", "same-origin"))
                .andExpect(status().isOk());
    }

    @Test
    void forcedLogoutIsRefused() throws Exception {
        Tokens login = AuthFlows.loginAlice(mvc);

        mvc.perform(post("/auth/logout").cookie(new Cookie(COOKIE, login.refreshToken())))
                .andExpect(status().isForbidden());

        assertThat(repository.findByTokenHash(sha256Hex(login.refreshToken())).orElseThrow().getRevokedAt()).isNull();
    }

    @Test
    void loginWithoutTheCustomHeaderIsRefused() throws Exception {
        // Login CSRF would sign the victim into the attacker's account.
        mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"%s\"}".formatted(ALICE_PASSWORD)))
                .andExpect(status().isForbidden());
    }

    @Test
    void theBearerApiDoesNotNeedTheHeader() throws Exception {
        // Browsers never attach Authorization headers on their own, so the API is not exposed to CSRF.
        String accessToken = AuthFlows.loginAlice(mvc).accessToken();
        mvc.perform(post("/api/orders")
                        .header(HttpHeaders.AUTHORIZATION, AuthFlows.bearer(accessToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"pen\",\"quantity\":1}"))
                .andExpect(status().isCreated());
    }
}
