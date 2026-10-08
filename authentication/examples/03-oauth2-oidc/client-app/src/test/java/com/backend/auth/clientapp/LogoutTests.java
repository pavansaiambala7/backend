package com.backend.auth.clientapp;

import static com.backend.auth.clientapp.BffTestSupport.ALICE_ID_TOKEN;
import static com.backend.auth.clientapp.BffTestSupport.REGISTRATION_ID;
import static com.backend.auth.clientapp.BffTestSupport.aliceLogin;
import static com.backend.auth.clientapp.BffTestSupport.queryParams;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    ClientRegistrationRepository clientRegistrations;

    @Test
    void logoutEndsTheLocalSessionAndRedirectsToTheProvidersEndSessionEndpoint() throws Exception {
        MockHttpSession session = new MockHttpSession();

        MvcResult result = mvc.perform(post("/logout").session(session).with(csrf()).with(aliceLogin(registration())))
                .andExpect(status().isFound())
                .andExpect(cookie().maxAge("BFF_SESSION", 0))
                .andReturn();

        // Local logout: the session, and with it every stored token, is gone.
        assertThat(session.isInvalid()).isTrue();

        // RP-initiated logout: the authorization server learns which session to end (id_token_hint) and
        // may only send the browser back to the registered post-logout URI.
        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("http://localhost:9000/connect/logout?");
        assertThat(queryParams(location))
                .containsEntry("id_token_hint", ALICE_ID_TOKEN)
                .containsEntry("post_logout_redirect_uri", "http://localhost/logged-out");
    }

    @Test
    void logoutWithoutCsrfTokenIsRefused() throws Exception {
        // Otherwise any web page could sign the user out with an auto-submitting form.
        MockHttpSession session = new MockHttpSession();
        mvc.perform(post("/logout").session(session).with(aliceLogin(registration())))
                .andExpect(status().isForbidden());
        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void getLogoutOnlyShowsAConfirmationPage() throws Exception {
        // A GET that logged out could be triggered by an <img> tag on any site. Spring Security answers
        // GET /logout with a confirmation page whose button sends the CSRF-protected POST.
        MockHttpSession session = new MockHttpSession();
        mvc.perform(get("/logout").session(session).with(aliceLogin(registration())))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist(HttpHeaders.LOCATION))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void loggedOutPageIsPublic() throws Exception {
        mvc.perform(get("/logged-out")).andExpect(status().isOk());
    }

    private ClientRegistration registration() {
        return clientRegistrations.findByRegistrationId(REGISTRATION_ID);
    }
}
