package com.backend.auth.clientapp;

import static com.backend.auth.clientapp.BffTestSupport.ALICE_ID_TOKEN;
import static com.backend.auth.clientapp.BffTestSupport.ISSUER;
import static com.backend.auth.clientapp.BffTestSupport.REGISTRATION_ID;
import static com.backend.auth.clientapp.BffTestSupport.aliceLogin;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SignedInUserTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    ClientRegistrationRepository clientRegistrations;

    @Test
    void meReturnsTheUserFromTheIdTokenButNoTokens() throws Exception {
        mvc.perform(get("/api/me").with(aliceLogin(registration())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.subject").value("alice"))
                .andExpect(jsonPath("$.name").value("Alice Anderson"))
                .andExpect(jsonPath("$.preferredUsername").value("alice"))
                .andExpect(jsonPath("$.authenticatedAt").value("2026-10-08T09:00:00Z"))
                // The whole point of the BFF: tokens never reach the browser.
                .andExpect(content().string(not(containsString(ALICE_ID_TOKEN))))
                .andExpect(jsonPath("$.idToken").doesNotExist())
                .andExpect(jsonPath("$.accessToken").doesNotExist());
    }

    @Test
    void homePageGreetsTheUserAndOffersACsrfProtectedLogout() throws Exception {
        mvc.perform(get("/").with(aliceLogin(registration())))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Signed in as <span>Alice Anderson</span>")))
                .andExpect(content().string(containsString("action=\"/logout\" method=\"post\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(content().string(not(containsString(ALICE_ID_TOKEN))))
                .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")));
    }

    private ClientRegistration registration() {
        return clientRegistrations.findByRegistrationId(REGISTRATION_ID);
    }
}
