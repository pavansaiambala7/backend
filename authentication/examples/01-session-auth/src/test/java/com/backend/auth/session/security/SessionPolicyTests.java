package com.backend.auth.session.security;

import static com.backend.auth.session.TestSupport.PASSWORD;
import static com.backend.auth.session.TestSupport.createAccount;
import static com.backend.auth.session.TestSupport.uniqueEmail;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.session.TestSupport;
import com.backend.auth.session.account.UserAccountRepository;

@SpringBootTest
@AutoConfigureMockMvc
class SessionPolicyTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    SessionPolicyProperties sessionPolicy;

    @Test
    void loggingInOnOneDeviceTooManyExpiresTheOldestSession() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "devices");
        List<MockHttpSession> sessions = new ArrayList<>();
        for (int i = 0; i <= sessionPolicy.maximumPerUser(); i++) {
            sessions.add(TestSupport.login(mvc, email));
        }

        mvc.perform(get("/").session(sessions.getFirst()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?expired"));
        mvc.perform(get("/").session(sessions.getLast()))
                .andExpect(status().isOk());
    }

    @Test
    void sessionEndsAtTheAbsoluteTimeoutEvenIfActive() throws Exception {
        MockHttpSession session = TestSupport.login(mvc, createAccount(accounts, passwordEncoder, "absolute"));
        mvc.perform(get("/").session(session)).andExpect(status().isOk());

        // Pretend the login happened just over the absolute timeout ago.
        Instant loginTime = Instant.now().minus(sessionPolicy.absoluteTimeout()).minus(Duration.ofSeconds(1));
        session.setAttribute(AbsoluteSessionTimeoutFilter.AUTHENTICATED_AT, loginTime);

        mvc.perform(get("/").session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?expired"));
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void loginRecordsTheAuthenticationTime() throws Exception {
        Instant before = Instant.now();

        MockHttpSession session = TestSupport.login(mvc, createAccount(accounts, passwordEncoder, "authtime"));

        assertThat(session.getAttribute(AbsoluteSessionTimeoutFilter.AUTHENTICATED_AT))
                .isInstanceOf(Instant.class)
                .satisfies(value -> assertThat((Instant) value).isAfterOrEqualTo(before));
    }

    @Test
    void crossSiteStateChangingRequestIsBlockedEvenWithAValidCsrfToken() throws Exception {
        String email = uniqueEmail("crosssite");

        mvc.perform(post("/register")
                        .param("email", email)
                        .param("password", PASSWORD)
                        .header("Sec-Fetch-Site", "cross-site")
                        .with(csrf()))
                .andExpect(status().isForbidden());

        assertThat(accounts.findByEmail(email)).isEmpty();
    }

    @Test
    void sameOriginRequestPassesTheFetchMetadataCheck() throws Exception {
        mvc.perform(post("/register")
                        .param("email", uniqueEmail("sameorigin"))
                        .param("password", PASSWORD)
                        .header("Sec-Fetch-Site", "same-origin")
                        .with(csrf()))
                .andExpect(redirectedUrl("/login?registered"));
    }
}
