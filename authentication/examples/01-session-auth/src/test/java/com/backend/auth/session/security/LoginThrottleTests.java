package com.backend.auth.session.security;

import static com.backend.auth.session.TestSupport.PASSWORD;
import static com.backend.auth.session.TestSupport.createAccount;
import static com.backend.auth.session.TestSupport.remoteAddr;
import static com.backend.auth.session.TestSupport.uniqueEmail;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.session.account.UserAccountRepository;

/**
 * End-to-end throttling through the real filter chain, with the default thresholds from
 * application.yml (5 failures per username + IP). Each test uses its own IP so tests stay independent.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginThrottleTests {

    private static final int MAX_FAILURES_PER_USER_AND_IP = 5;
    private static final String WRONG_PASSWORD = "not the right passphrase";

    @Autowired
    MockMvc mvc;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void afterNFailuresEvenTheCorrectPasswordIsRefused() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "throttled");
        String ip = "203.0.113.10";

        for (int i = 0; i < MAX_FAILURES_PER_USER_AND_IP; i++) {
            attempt(email, WRONG_PASSWORD, ip).andExpect(redirectedUrl("/login?error"));
        }

        // Refused before the password is checked, so a blocked attacker cannot confirm a correct guess.
        attempt(email, PASSWORD, ip)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", matchesPattern("[1-9]|[12][0-9]|30")))  // first block: 30 s
                .andExpect(unauthenticated());
    }

    @Test
    void throttleLooksTheSameForUnknownUsernames() throws Exception {
        String existing = createAccount(accounts, passwordEncoder, "known");
        String unknown = uniqueEmail("unknown");

        MvcResult existingBlocked = failUntilBlocked(existing, "203.0.113.20");
        MvcResult unknownBlocked = failUntilBlocked(unknown, "203.0.113.21");

        assertThat(unknownBlocked.getResponse().getStatus()).isEqualTo(429);
        assertThat(unknownBlocked.getResponse().getStatus()).isEqualTo(existingBlocked.getResponse().getStatus());
        assertThat(withoutDigits(unknownBlocked.getResponse().getContentAsString()))
                .isEqualTo(withoutDigits(existingBlocked.getResponse().getContentAsString()));
    }

    @Test
    void attackerAtOneIpDoesNotLockOutTheUserElsewhere() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "victim");
        failUntilBlocked(email, "203.0.113.30");

        attempt(email, PASSWORD, "198.51.100.30")
                .andExpect(redirectedUrl("/"))
                .andExpect(authenticated().withUsername(email));
    }

    @Test
    void successfulLoginResetsTheCounterForThatUserAndIp() throws Exception {
        String email = createAccount(accounts, passwordEncoder, "reset");
        String ip = "203.0.113.40";

        for (int i = 0; i < MAX_FAILURES_PER_USER_AND_IP - 1; i++) {
            attempt(email, WRONG_PASSWORD, ip);
        }
        attempt(email, PASSWORD, ip).andExpect(authenticated());
        for (int i = 0; i < MAX_FAILURES_PER_USER_AND_IP - 1; i++) {
            attempt(email, WRONG_PASSWORD, ip);
        }

        attempt(email, PASSWORD, ip).andExpect(authenticated());
    }

    /** The body contains the remaining seconds, which may differ by one between two requests. */
    private static String withoutDigits(String text) {
        return text.replaceAll("\\d", "");
    }

    private MvcResult failUntilBlocked(String email, String ip) throws Exception {
        for (int i = 0; i < MAX_FAILURES_PER_USER_AND_IP; i++) {
            attempt(email, WRONG_PASSWORD, ip);
        }
        return attempt(email, WRONG_PASSWORD, ip).andReturn();
    }

    private ResultActions attempt(String email, String password, String ip) throws Exception {
        return mvc.perform(post("/login")
                .param("username", email)
                .param("password", password)
                .with(csrf())
                .with(remoteAddr(ip)));
    }
}
