package com.backend.auth.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;

import com.backend.auth.mfa.otp.Base32;
import com.backend.auth.mfa.otp.Totp;

/**
 * Base for tests that drive the real filter chain through MockMvc. Every test creates its own user, so tests are
 * independent; time is a {@link MutableClock} so TOTP steps, throttle blocks and timeouts need no sleeping.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestClockConfiguration.class)
public abstract class MfaFlowTest {

    /** Test-only password for generated users. */
    protected static final String PASSWORD = "integration-test-passphrase";
    protected static final Totp TOTP = Totp.authenticatorAppDefaults();

    private static final Pattern SECRET = Pattern.compile("id=\"secret\"[^>]*>([A-Z2-7]+)<");
    private static final Pattern RECOVERY_CODE = Pattern.compile("class=\"recovery-code\"[^>]*>([A-Z2-7-]+)<");

    /** A user with an active authenticator. */
    protected record EnrolledUser(String username, String secret, List<String> recoveryCodes) {
    }

    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected MutableClock clock;

    @Autowired
    private InMemoryUserDetailsManager users;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void startAtTheRealTime() {
        // Spring's form login stamps FACTOR_PASSWORD with the system clock, so the test clock starts there too.
        clock.setInstant(Instant.now());
    }

    protected String createUser() {
        String username = "user-" + UUID.randomUUID();
        users.createUser(User.withUsername(username).password(passwordEncoder.encode(PASSWORD)).roles("USER").build());
        return username;
    }

    /** Step 1 through the real form-login endpoint; returns the partially authenticated session. */
    protected MockHttpSession loginWithPassword(String username) throws Exception {
        return (MockHttpSession) mvc.perform(post("/login")
                        .param("username", username)
                        .param("password", PASSWORD)
                        .with(csrf()))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/"))
                .andReturn().getRequest().getSession(false);
    }

    /** Starts enrollment in a session that passed the password step; returns the rendered Base32 secret. */
    protected String startEnrollment(MockHttpSession session) throws Exception {
        String page = mvc.perform(post("/mfa/totp/enroll").session(session).with(csrf()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return secretIn(page);
    }

    protected ResultActions confirmEnrollment(MockHttpSession session, String code) throws Exception {
        return mvc.perform(post("/mfa/totp/confirm").session(session).param("code", code).with(csrf()));
    }

    /**
     * Creates a user and runs the whole enrollment. Afterwards the clock is one step later, because the code that
     * confirmed enrollment has used up its time step.
     */
    protected EnrolledUser enrolledUser() throws Exception {
        String username = createUser();
        MockHttpSession session = loginWithPassword(username);
        String secret = startEnrollment(session);
        String page = confirmEnrollment(session, currentCode(secret))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        clock.advance(TOTP.period());
        return new EnrolledUser(username, secret, all(RECOVERY_CODE, page));
    }

    protected ResultActions submitTotp(MockHttpSession session, String code) throws Exception {
        return mvc.perform(post("/login/totp").session(session).param("code", code).with(csrf()));
    }

    protected ResultActions submitRecoveryCode(MockHttpSession session, String code) throws Exception {
        return mvc.perform(post("/login/recovery-code").session(session).param("code", code).with(csrf()));
    }

    /** Password, then the current TOTP code: a fully authenticated session. */
    protected MockHttpSession fullLogin(EnrolledUser user) throws Exception {
        MockHttpSession session = loginWithPassword(user.username());
        submitTotp(session, currentCode(user.secret())).andExpect(redirectedUrl("/"));
        return session;
    }

    protected String currentCode(String secret) {
        return codeAtStepOffset(secret, 0);
    }

    protected String codeAtStepOffset(String secret, int steps) {
        return TOTP.codeAt(Base32.decode(secret), TOTP.timeStep(clock.instant()) + steps);
    }

    /**
     * The redirect Spring Security sends when the TOTP or recovery-code factor is missing. Its query string names the
     * missing factors, e.g. {@code /login/totp?factor.type=totp&factor.type=recovery_code&factor.reason=missing...}.
     */
    protected static ResultMatcher redirectedToSecondStep() {
        return result -> {
            String location = result.getResponse().getRedirectedUrl();
            assertThat(location).as("redirect").isNotNull();
            assertThat(location).startsWith("/login/totp?").contains("factor.type=totp", "factor.reason=missing");
        };
    }

    /** The authorities stored in the session, i.e. what the next request will be authorized with. */
    protected static List<String> sessionAuthorities(MockHttpSession session) {
        SecurityContext context = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication = context.getAuthentication();
        return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }

    protected static String secretIn(String page) {
        return first(SECRET, page);
    }

    protected static List<String> recoveryCodesIn(String page) {
        return all(RECOVERY_CODE, page);
    }

    private static String first(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            throw new AssertionError("No match for " + pattern + " in:\n" + text);
        }
        return matcher.group(1);
    }

    private static List<String> all(Pattern pattern, String text) {
        return pattern.matcher(text).results().map(result -> result.group(1)).toList();
    }
}
