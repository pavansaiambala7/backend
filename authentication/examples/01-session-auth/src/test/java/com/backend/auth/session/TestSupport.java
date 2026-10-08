package com.backend.auth.session;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

import java.time.Instant;
import java.util.UUID;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.backend.auth.session.account.UserAccount;
import com.backend.auth.session.account.UserAccountRepository;

/** Helpers shared by the MockMvc tests. Every test uses its own email address, so tests stay independent. */
public final class TestSupport {

    /** Long enough for the policy and not on the blocklist. Test-only value. */
    public static final String PASSWORD = "plaid otter sings at dawn";

    private TestSupport() {
    }

    public static String uniqueEmail(String prefix) {
        return prefix + "-" + UUID.randomUUID() + "@example.com";
    }

    /** Inserts an account directly (faster than the HTTP registration flow). */
    public static String createAccount(UserAccountRepository accounts, PasswordEncoder encoder, String prefix) {
        String email = uniqueEmail(prefix);
        accounts.saveAndFlush(new UserAccount(email, encoder.encode(PASSWORD), Instant.now()));
        return email;
    }

    /** Logs in through the real form-login endpoint and returns the authenticated session. */
    public static MockHttpSession login(MockMvc mvc, String email) throws Exception {
        MvcResult result = mvc.perform(post("/login")
                        .param("username", email)
                        .param("password", PASSWORD)
                        .with(csrf()))
                .andExpect(redirectedUrl("/"))
                .andReturn();
        return (MockHttpSession) result.getRequest().getSession(false);
    }

    /** Simulates requests from a specific client IP (throttling keys include the IP). */
    public static RequestPostProcessor remoteAddr(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }
}
