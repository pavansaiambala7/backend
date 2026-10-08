package com.backend.auth.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

class TotpLoginTests extends MfaFlowTest {

    @Test
    void anonymousRequestsAreSentToThePasswordStep() throws Exception {
        mvc.perform(get("/")).andExpect(redirectedUrl("/login"));
        mvc.perform(get("/login/totp")).andExpect(redirectedUrl("/login"));
        // A code alone identifies nobody.
        mvc.perform(post("/login/totp").param("code", "123456").with(csrf())).andExpect(redirectedUrl("/login"));
    }

    @Test
    void passwordOnlySessionCannotReachProtectedPages() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());

        assertThat(sessionAuthorities(session)).contains("FACTOR_PASSWORD").doesNotContain("FACTOR_TOTP");
        mvc.perform(get("/").session(session)).andExpect(redirectedToSecondStep());
        mvc.perform(get("/any/other/page").session(session)).andExpect(redirectedToSecondStep());
        mvc.perform(post("/mfa/recovery-codes").session(session).with(csrf())).andExpect(redirectedToSecondStep());
        // Only the second-step pages are open to it.
        mvc.perform(get("/login/totp").session(session)).andExpect(status().isOk());
        mvc.perform(get("/login/recovery-code").session(session)).andExpect(status().isOk());
    }

    @Test
    void validCodeCompletesTheLoginWithANewSessionId() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());
        String idAfterPassword = session.getId();

        submitTotp(session, currentCode(user.secret())).andExpect(redirectedUrl("/"));

        // Privilege went up, so the session ID changed again (session fixation defense for the second step).
        assertThat(session.getId()).isNotEqualTo(idAfterPassword);
        assertThat(sessionAuthorities(session)).contains("ROLE_USER", "FACTOR_PASSWORD", "FACTOR_TOTP");
        mvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(user.username())))
                .andExpect(content().string(containsString("FACTOR_TOTP")));
    }

    @Test
    void afterSecondFactorTheUserReturnsToThePageTheyAskedFor() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());
        mvc.perform(get("/?tab=security").session(session)).andExpect(redirectedToSecondStep());

        submitTotp(session, currentCode(user.secret())).andExpect(redirectedUrl("http://localhost/?tab=security&continue"));
    }

    @Test
    void wrongCodeFailsAndTheSessionStaysPartial() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());

        submitTotp(session, codeAtStepOffset(user.secret(), 3)).andExpect(redirectedUrl("/login/totp?error"));
        submitTotp(session, "not-a-code").andExpect(redirectedUrl("/login/totp?error"));

        assertThat(sessionAuthorities(session)).doesNotContain("FACTOR_TOTP");
        mvc.perform(get("/").session(session)).andExpect(redirectedToSecondStep());
    }

    @Test
    void aCodeIsAcceptedOnlyOnce() throws Exception {
        EnrolledUser user = enrolledUser();
        String code = currentCode(user.secret());
        fullLogin(user);

        // Same code, same 30 seconds, new session: someone who saw or relayed the code tries to use it.
        MockHttpSession attacker = loginWithPassword(user.username());
        submitTotp(attacker, code).andExpect(redirectedUrl("/login/totp?error"));

        clock.advance(TOTP.period());
        submitTotp(attacker, currentCode(user.secret())).andExpect(redirectedUrl("/"));
    }

    @Test
    void oneStepOfClockDriftIsToleratedButNotMore() throws Exception {
        EnrolledUser user = enrolledUser();
        clock.advance(TOTP.period().multipliedBy(2));
        MockHttpSession session = loginWithPassword(user.username());

        submitTotp(session, codeAtStepOffset(user.secret(), -2)).andExpect(redirectedUrl("/login/totp?error"));
        submitTotp(session, codeAtStepOffset(user.secret(), +2)).andExpect(redirectedUrl("/login/totp?error"));
        submitTotp(session, codeAtStepOffset(user.secret(), +1)).andExpect(redirectedUrl("/"));

        // The previous step's code is inside the window, but older than the step just used: rejected.
        MockHttpSession another = loginWithPassword(user.username());
        submitTotp(another, codeAtStepOffset(user.secret(), -1)).andExpect(redirectedUrl("/login/totp?error"));
    }

    @Test
    void theSecondStepMustFollowThePasswordWithinFiveMinutes() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());

        clock.advance(Duration.ofMinutes(5).plusSeconds(1));

        // Spring Security's missing-factor handling says which factor and why in the redirect.
        mvc.perform(get("/login/totp").session(session))
                .andExpect(redirectedUrl("/login?factor.type=password&factor.reason=expired"));
        submitTotp(session, currentCode(user.secret())).andExpect(redirectedUrl("/login"));
    }

    @Test
    void wrongCodesAreThrottledPerAccountNotPerSession() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());
        for (int i = 0; i < 5; i++) {
            submitTotp(session, codeAtStepOffset(user.secret(), 5)).andExpect(redirectedUrl("/login/totp?error"));
        }

        // Even the right code is refused now, and a fresh session (password entered again) does not help.
        submitTotp(session, currentCode(user.secret()))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "30"));
        submitTotp(loginWithPassword(user.username()), currentCode(user.secret()))
                .andExpect(status().isTooManyRequests());

        clock.advance(Duration.ofSeconds(30));
        submitTotp(session, currentCode(user.secret())).andExpect(redirectedUrl("/"));
    }

    @Test
    void codeSubmissionRequiresTheCsrfToken() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());

        mvc.perform(post("/login/totp").session(session).param("code", currentCode(user.secret())))
                .andExpect(status().isForbidden());
    }

    @Test
    void logoutEndsAPartiallyAuthenticatedSession() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());

        mvc.perform(post("/logout").session(session).with(csrf())).andExpect(redirectedUrl("/login?logout"));

        assertThat(session.isInvalid()).isTrue();
    }
}
