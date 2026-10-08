package com.backend.auth.session;

import static com.backend.auth.session.TestSupport.PASSWORD;
import static com.backend.auth.session.TestSupport.createAccount;
import static com.backend.auth.session.TestSupport.uniqueEmail;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.backend.auth.session.account.UserAccount;
import com.backend.auth.session.account.UserAccountRepository;

@SpringBootTest
@AutoConfigureMockMvc
class LoginTests {

    private static final String GENERIC_LOGIN_ERROR = "Invalid email or password.";

    @Autowired
    MockMvc mvc;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void protectedPageRequiresLogin() throws Exception {
        mvc.perform(get("/"))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void loginCreatesAnAuthenticatedSessionWithANewSessionId() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "login");
        // An anonymous session that already exists before login, as an attacker could plant one.
        MockHttpSession session = new MockHttpSession();
        String sessionIdBeforeLogin = session.getId();

        MvcResult result = mvc.perform(post("/login")
                        .session(session)
                        .param("username", email)
                        .param("password", PASSWORD)
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(email).withRoles("USER"))
                .andReturn();

        MockHttpSession authenticatedSession = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(authenticatedSession).isNotNull();
        // Session fixation defense: the pre-login ID is no longer the session's ID.
        assertThat(authenticatedSession.getId()).isNotEqualTo(sessionIdBeforeLogin);

        mvc.perform(get("/").session(authenticatedSession))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(email)));
    }

    @Test
    void wrongPasswordFailsWithTheGenericMessage() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "wrongpw");

        mvc.perform(post("/login").param("username", email).param("password", "not the right passphrase").with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?error"))
                .andExpect(unauthenticated());

        mvc.perform(get("/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(GENERIC_LOGIN_ERROR)));
    }

    @Test
    void unknownUserFailsExactlyLikeAWrongPassword() throws Exception {
        String existing = createAccount(accounts, passwordEncoder, "exists");
        String unknown = uniqueEmail("ghost");

        MvcResult wrongPassword = mvc.perform(post("/login")
                        .param("username", existing).param("password", "not the right passphrase").with(csrf()))
                .andReturn();
        MvcResult unknownUser = mvc.perform(post("/login")
                        .param("username", unknown).param("password", "not the right passphrase").with(csrf()))
                .andReturn();

        assertThat(unknownUser.getResponse().getStatus()).isEqualTo(wrongPassword.getResponse().getStatus());
        assertThat(unknownUser.getResponse().getRedirectedUrl()).isEqualTo(wrongPassword.getResponse().getRedirectedUrl());
    }

    @Test
    void loginWithoutCsrfTokenIsRejected() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "logincsrf");

        // Login CSRF: without the token an attacker's page could sign the victim into the attacker's account.
        mvc.perform(post("/login").param("username", email).param("password", PASSWORD))
                .andExpect(status().isForbidden())
                .andExpect(unauthenticated());
    }

    @Test
    void loginPageContainsCsrfTokenAndSecurityHeaders() throws Exception {
        mvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(result -> assertThat(result.getResponse().getHeader("Content-Security-Policy"))
                        .contains("default-src 'self'", "frame-ancestors 'none'"))
                .andExpect(result -> assertThat(result.getResponse().getHeader("Cache-Control")).contains("no-store"));
    }

    @Test
    void legacyBcryptHashIsUpgradedToArgon2idOnLogin() throws Exception {
        String email = uniqueEmail("legacy");
        String legacyHash = "{bcrypt}" + new BCryptPasswordEncoder(10).encode(PASSWORD);
        accounts.saveAndFlush(new UserAccount(email, legacyHash, Instant.now()));

        TestSupport.login(mvc, email);

        String upgradedHash = accounts.findByEmail(email).orElseThrow().getPasswordHash();
        assertThat(upgradedHash).startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(passwordEncoder.matches(PASSWORD, upgradedHash)).isTrue();
    }
}
