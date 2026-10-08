package com.backend.auth.session;

import static com.backend.auth.session.TestSupport.createAccount;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.session.account.UserAccountRepository;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutTests {

    /** server.servlet.session.cookie.name in the default profile. */
    private static final String SESSION_COOKIE = "SESSION";

    @Autowired
    MockMvc mvc;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void logoutInvalidatesTheSessionAndDeletesTheCookie() throws Exception {
        MockHttpSession session = TestSupport.login(mvc, createAccount(accounts, passwordEncoder, "logout"));

        mvc.perform(post("/logout").session(session).with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?logout"))
                .andExpect(cookie().maxAge(SESSION_COOKIE, 0))
                .andExpect(unauthenticated());

        // Invalidated server-side: a stolen copy of the old session ID is now worthless.
        assertThat(session.isInvalid()).isTrue();
        mvc.perform(get("/").session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    void logoutWithoutCsrfTokenIsRejectedAndTheSessionSurvives() throws Exception {
        MockHttpSession session = TestSupport.login(mvc, createAccount(accounts, passwordEncoder, "logoutcsrf"));

        mvc.perform(post("/logout").session(session)).andExpect(status().isForbidden());

        assertThat(session.isInvalid()).isFalse();
        mvc.perform(get("/").session(session)).andExpect(status().isOk());
    }

    @Test
    void getRequestCannotLogTheUserOut() throws Exception {
        MockHttpSession session = TestSupport.login(mvc, createAccount(accounts, passwordEncoder, "logoutget"));

        // An <img src="https://app/logout"> on another site must not end the session.
        mvc.perform(get("/logout").session(session));

        assertThat(session.isInvalid()).isFalse();
        mvc.perform(get("/").session(session)).andExpect(status().isOk());
    }
}
