package com.backend.auth.session;

import static com.backend.auth.session.TestSupport.PASSWORD;
import static com.backend.auth.session.TestSupport.uniqueEmail;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.session.account.UserAccount;
import com.backend.auth.session.account.UserAccountRepository;

@SpringBootTest
@AutoConfigureMockMvc
class RegistrationTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    UserAccountRepository accounts;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void registrationStoresAnArgon2idHashNeverThePassword() throws Exception {
        String email = uniqueEmail("argon");

        register(email, PASSWORD)
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?registered"));

        UserAccount account = accounts.findByEmail(email).orElseThrow();
        // {argon2} = DelegatingPasswordEncoder id; argon2id with the OWASP minimum parameters.
        assertThat(account.getPasswordHash())
                .startsWith("{argon2}$argon2id$v=19$m=19456,t=2,p=1$")
                .doesNotContain(PASSWORD);
        assertThat(passwordEncoder.matches(PASSWORD, account.getPasswordHash())).isTrue();
    }

    @Test
    void emailIsNormalizedSoCaseVariantsAreOneAccount() throws Exception {
        String email = uniqueEmail("case");

        register(email.toUpperCase(), PASSWORD).andExpect(redirectedUrl("/login?registered"));

        assertThat(accounts.findByEmail(email)).isPresent();
    }

    @Test
    void registeredUserCanSignIn() throws Exception {
        String email = uniqueEmail("signin");
        register(email, PASSWORD).andExpect(redirectedUrl("/login?registered"));

        TestSupport.login(mvc, email);
    }

    @Test
    void postWithoutCsrfTokenIsRejected() throws Exception {
        String email = uniqueEmail("nocsrf");

        mvc.perform(post("/register").param("email", email).param("password", PASSWORD))
                .andExpect(status().isForbidden());

        assertThat(accounts.findByEmail(email)).isEmpty();
    }

    @Test
    void postWithInvalidCsrfTokenIsRejected() throws Exception {
        String email = uniqueEmail("badcsrf");

        mvc.perform(post("/register").param("email", email).param("password", PASSWORD).with(csrf().useInvalidToken()))
                .andExpect(status().isForbidden());

        assertThat(accounts.findByEmail(email)).isEmpty();
    }

    @Test
    void registrationFormContainsCsrfToken() throws Exception {
        mvc.perform(get("/register"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    @Test
    void shortPasswordIsRejectedWithAReason() throws Exception {
        String email = uniqueEmail("short");

        register(email, "Tr0ub4dor&3")   // complex but short: length beats composition
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Use at least 15 characters")));

        assertThat(accounts.findByEmail(email)).isEmpty();
    }

    @Test
    void breachedPasswordIsRejectedWithAReason() throws Exception {
        String email = uniqueEmail("breached");

        register(email, "correct horse battery staple")
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("breached or common passwords")));

        assertThat(accounts.findByEmail(email)).isEmpty();
    }

    @Test
    void duplicateRegistrationLooksIdenticalAndDoesNotOverwriteTheAccount() throws Exception {
        String email = uniqueEmail("dup");
        register(email, PASSWORD).andExpect(redirectedUrl("/login?registered"));
        String originalHash = accounts.findByEmail(email).orElseThrow().getPasswordHash();

        // Same status and redirect as a fresh registration: the response does not reveal the account exists.
        register(email, "a completely different passphrase")
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?registered"));

        assertThat(accounts.findByEmail(email).orElseThrow().getPasswordHash()).isEqualTo(originalHash);
    }

    private ResultActions register(String email, String password) throws Exception {
        return mvc.perform(post("/register")
                .param("email", email)
                .param("password", password)
                .with(csrf()));
    }
}
