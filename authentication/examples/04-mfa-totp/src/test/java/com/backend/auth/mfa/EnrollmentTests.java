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

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;

import com.backend.auth.mfa.crypto.SecretEncryptor;
import com.backend.auth.mfa.otp.Base32;
import com.backend.auth.mfa.totp.TotpCredential;
import com.backend.auth.mfa.totp.TotpCredentialRepository;

class EnrollmentTests extends MfaFlowTest {

    @Autowired
    TotpCredentialRepository credentials;

    @Autowired
    SecretEncryptor encryptor;

    @Test
    void userWithoutAuthenticatorIsSentToEnrollmentAfterThePassword() throws Exception {
        MockHttpSession session = loginWithPassword(createUser());

        mvc.perform(get("/").session(session)).andExpect(redirectedToSecondStep());
        mvc.perform(get("/login/totp").session(session)).andExpect(redirectedUrl("/mfa/totp/enroll"));
        mvc.perform(get("/mfa/totp/enroll").session(session)).andExpect(status().isOk());
    }

    @Test
    void enrollmentShowsA160BitBase32SecretAndAnOtpauthUri() throws Exception {
        String username = createUser();
        MockHttpSession session = loginWithPassword(username);

        String page = mvc.perform(post("/mfa/totp/enroll").session(session).with(csrf()))
                .andExpect(status().isOk())
                // Pages carrying secrets must not be cached (Spring Security's default header).
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andReturn().getResponse().getContentAsString();
        String secret = secretIn(page);

        assertThat(secret).matches("[A-Z2-7]{32}");
        assertThat(Base32.decode(secret)).hasSize(20);
        assertThat(page).contains("otpauth://totp/Auth%20Guide%20Demo:" + username + "?secret=");
        assertThat(page).contains("&amp;issuer=Auth%20Guide%20Demo&amp;algorithm=SHA1&amp;digits=6&amp;period=30");
    }

    @Test
    void secretIsStoredEncryptedAndBoundToItsOwner() throws Exception {
        String username = createUser();
        String secret = startEnrollment(loginWithPassword(username));

        TotpCredential stored = credentials.findByUsername(username).orElseThrow();
        assertThat(stored.active()).isFalse();
        assertThat(stored.encryptedSecret()).startsWith("demo-1:").doesNotContain(secret);
        assertThat(encryptor.decrypt(stored.encryptedSecret(), "totp-secret:" + username)).isEqualTo(Base32.decode(secret));
    }

    @Test
    void wrongConfirmationCodeDoesNotActivateTheAuthenticator() throws Exception {
        String username = createUser();
        MockHttpSession session = loginWithPassword(username);
        String secret = startEnrollment(session);

        confirmEnrollment(session, codeAtStepOffset(secret, 5))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("That code is not valid")))
                .andExpect(content().string(containsString(secret)));   // same pending secret, shown again

        assertThat(credentials.isActive(username)).isFalse();
    }

    @Test
    void validCodeActivatesTheAuthenticatorAndShowsTenRecoveryCodesOnce() throws Exception {
        String username = createUser();
        MockHttpSession session = loginWithPassword(username);
        String secret = startEnrollment(session);

        String page = confirmEnrollment(session, currentCode(secret))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        List<String> codes = recoveryCodesIn(page);
        assertThat(codes).hasSize(10).doesNotHaveDuplicates()
                .allSatisfy(code -> assertThat(code).matches("[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}"));
        assertThat(credentials.isActive(username)).isTrue();
    }

    @Test
    void confirmingDoesNotSignTheUserInAndTheConfirmationCodeCannotBeReplayed() throws Exception {
        String username = createUser();
        MockHttpSession session = loginWithPassword(username);
        String secret = startEnrollment(session);
        String confirmationCode = currentCode(secret);
        confirmEnrollment(session, confirmationCode).andExpect(status().isOk());

        // Still only the password factor: the second factor is proven at the login step.
        mvc.perform(get("/").session(session)).andExpect(redirectedToSecondStep());
        submitTotp(session, confirmationCode).andExpect(redirectedUrl("/login/totp?error"));

        clock.advance(TOTP.period());
        // Back to the page that sent the user to the second step ("continue" marks a saved request).
        submitTotp(session, currentCode(secret)).andExpect(redirectedUrl("http://localhost/?continue"));
    }

    @Test
    void anAccountWithAnAuthenticatorCannotEnrollAnotherWithThePasswordAlone() throws Exception {
        EnrolledUser user = enrolledUser();
        MockHttpSession passwordOnly = loginWithPassword(user.username());

        // Otherwise anyone who learned the password could replace the victim's authenticator with their own.
        mvc.perform(get("/mfa/totp/enroll").session(passwordOnly)).andExpect(status().isForbidden());
        mvc.perform(post("/mfa/totp/enroll").session(passwordOnly).with(csrf())).andExpect(status().isForbidden());
        mvc.perform(post("/mfa/totp/confirm").session(passwordOnly).param("code", currentCode(user.secret())).with(csrf()))
                .andExpect(status().isForbidden());
    }

    @Test
    void enrollmentRequiresThePasswordStepAndCsrfToken() throws Exception {
        mvc.perform(get("/mfa/totp/enroll")).andExpect(redirectedUrl("/login"));

        MockHttpSession session = loginWithPassword(createUser());
        mvc.perform(post("/mfa/totp/enroll").session(session)).andExpect(status().isForbidden());
    }

    @Test
    void enrollmentConfirmationIsThrottled() throws Exception {
        MockHttpSession session = loginWithPassword(createUser());
        String secret = startEnrollment(session);
        for (int i = 0; i < 5; i++) {
            confirmEnrollment(session, "000000").andExpect(status().isBadRequest());
        }

        confirmEnrollment(session, currentCode(secret))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "30"));
    }
}
