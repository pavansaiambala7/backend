package com.backend.auth.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;

class RecoveryCodeTests extends MfaFlowTest {

    @Autowired
    JdbcClient jdbc;

    @Test
    void aRecoveryCodeCompletesTheLoginExactlyOnce() throws Exception {
        EnrolledUser user = enrolledUser();
        String code = user.recoveryCodes().get(0);

        MockHttpSession session = loginWithPassword(user.username());
        submitRecoveryCode(session, code).andExpect(redirectedUrl("/"));

        // Recorded as its own factor, so the application knows the authenticator was bypassed.
        assertThat(sessionAuthorities(session)).contains("FACTOR_PASSWORD", "FACTOR_RECOVERY_CODE").doesNotContain("FACTOR_TOTP");
        mvc.perform(get("/").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("You signed in with a recovery code")))
                .andExpect(content().string(containsString("<span id=\"recovery-codes-left\">9</span>")));

        MockHttpSession secondAttempt = loginWithPassword(user.username());
        submitRecoveryCode(secondAttempt, code).andExpect(redirectedUrl("/login/recovery-code?error"));
        mvc.perform(get("/").session(secondAttempt)).andExpect(redirectedToSecondStep());
    }

    @Test
    void codesAreAcceptedInAnyCaseWithOrWithoutDashes() throws Exception {
        EnrolledUser user = enrolledUser();
        String typedSloppily = " " + user.recoveryCodes().get(3).replace("-", "").toLowerCase(Locale.ROOT) + " ";

        submitRecoveryCode(loginWithPassword(user.username()), typedSloppily).andExpect(redirectedUrl("/"));
    }

    @Test
    void codesAreStoredOnlyAsSaltedArgon2idHashes() throws Exception {
        EnrolledUser user = enrolledUser();

        List<String> hashes = jdbc.sql("select code_hash from recovery_code where username = :username")
                .param("username", user.username())
                .query(String.class)
                .list();

        assertThat(hashes).hasSize(10).doesNotHaveDuplicates()
                .allSatisfy(hash -> assertThat(hash).startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$"));
        for (String code : user.recoveryCodes()) {
            assertThat(hashes).noneMatch(hash -> hash.contains(code) || hash.contains(code.replace("-", "")));
        }
    }

    @Test
    void anotherUsersCodeDoesNotWork() throws Exception {
        EnrolledUser alice = enrolledUser();
        EnrolledUser bob = enrolledUser();

        submitRecoveryCode(loginWithPassword(bob.username()), alice.recoveryCodes().get(0))
                .andExpect(redirectedUrl("/login/recovery-code?error"));
    }

    @Test
    void generatingNewCodesInvalidatesTheOldOnes() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = fullLogin(user);

        String page = mvc.perform(post("/mfa/recovery-codes").session(session).with(csrf()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        List<String> newCodes = recoveryCodesIn(page);

        assertThat(newCodes).hasSize(10).doesNotContainAnyElementsOf(user.recoveryCodes());
        submitRecoveryCode(loginWithPassword(user.username()), user.recoveryCodes().get(1))
                .andExpect(redirectedUrl("/login/recovery-code?error"));
        submitRecoveryCode(loginWithPassword(user.username()), newCodes.get(1)).andExpect(redirectedUrl("/"));
    }

    @Test
    void recoveryCodesNeedThePasswordStepFirst() throws Exception {
        EnrolledUser user = enrolledUser();

        mvc.perform(post("/login/recovery-code").param("code", user.recoveryCodes().get(0)).with(csrf()))
                .andExpect(redirectedUrl("/login"));
        // Not consumed by the rejected attempt.
        submitRecoveryCode(loginWithPassword(user.username()), user.recoveryCodes().get(0)).andExpect(redirectedUrl("/"));
    }

    @Test
    void recoveryCodesShareTheThrottleWithTotpCodes() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession session = loginWithPassword(user.username());
        for (int i = 0; i < 3; i++) {
            submitTotp(session, codeAtStepOffset(user.secret(), 5)).andExpect(redirectedUrl("/login/totp?error"));
        }
        for (int i = 0; i < 2; i++) {
            submitRecoveryCode(session, "AAAA-AAAA-AAAA-AAAA").andExpect(redirectedUrl("/login/recovery-code?error"));
        }

        submitRecoveryCode(session, user.recoveryCodes().get(0)).andExpect(status().isTooManyRequests());
    }
}
