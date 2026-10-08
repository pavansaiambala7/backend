package com.backend.auth.clientapp;

import static com.backend.auth.clientapp.BffTestSupport.REGISTRATION_ID;
import static com.backend.auth.clientapp.BffTestSupport.aliceAuthentication;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.backend.auth.clientapp.FakeHttpServer.RecordedRequest;
import com.backend.auth.clientapp.FakeHttpServer.Response;

/**
 * The BFF calling the resource server for the signed-in user. A local fake plays both the orders API
 * and the authorization server's token endpoint, so the test can see exactly what the BFF sends.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OrdersProxyTests {

    private static final FakeHttpServer FAKE = FakeHttpServer.start();

    private static final String ALICE_ORDERS = """
            {"subject":"alice","clientId":"bff-client","orders":[
              {"id":"A-1001","owner":"alice","item":"Mechanical keyboard","total":129.00}]}
            """;

    @DynamicPropertySource
    static void useFakeServers(DynamicPropertyRegistry registry) {
        registry.add("bff.orders-api.base-url", FAKE::baseUrl);
        registry.add("bff.provider.token-uri", () -> FAKE.baseUrl() + "/oauth2/token");
    }

    @AfterAll
    static void stopFakeServers() {
        FAKE.close();
    }

    @Autowired
    MockMvc mvc;

    @Autowired
    ClientRegistrationRepository clientRegistrations;

    @Autowired
    OAuth2AuthorizedClientRepository authorizedClients;

    @BeforeEach
    void resetFake() {
        FAKE.reset();
    }

    @Test
    void ordersAreFetchedWithTheUsersAccessTokenWhichNeverReachesTheBrowser() throws Exception {
        FAKE.respond("/api/orders", request -> Response.json(ALICE_ORDERS));
        MockHttpSession session = sessionHoldingTokens(validAccessToken("alice-access-token"), "alice-refresh-token");

        mvc.perform(get("/api/orders").session(session).with(authentication(aliceAuthentication())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"))
                .andExpect(jsonPath("$.orders[0].id").value("A-1001"))
                .andExpect(jsonPath("$.orders[0].item").value("Mechanical keyboard"))
                .andExpect(content().string(not(containsString("alice-access-token"))))
                .andExpect(content().string(not(containsString("alice-refresh-token"))));

        assertThat(FAKE.requestsTo("/api/orders")).singleElement()
                .extracting(RecordedRequest::authorization).isEqualTo("Bearer alice-access-token");
    }

    @Test
    void expiredAccessTokenIsRefreshedOnTheServerAndTheRotatedRefreshTokenIsKept() throws Exception {
        FAKE.respond("/oauth2/token", request -> Response.json("""
                {"access_token":"fresh-access-token","token_type":"Bearer","expires_in":600,
                 "refresh_token":"rotated-refresh-token","scope":"openid profile orders.read"}
                """));
        FAKE.respond("/api/orders", request -> Response.json(ALICE_ORDERS));
        Instant issued = Instant.now().minus(Duration.ofMinutes(20));
        OAuth2AccessToken expired = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired-access-token",
                issued, issued.plus(Duration.ofMinutes(10)), Set.of("openid", "profile", "orders.read"));
        MockHttpSession session = sessionHoldingTokens(expired, "first-refresh-token");

        mvc.perform(get("/api/orders").session(session).with(authentication(aliceAuthentication())))
                .andExpect(status().isOk());

        // The refresh happened on the back channel, authenticated with the client's credentials.
        assertThat(FAKE.requestsTo("/oauth2/token")).singleElement().satisfies(tokenRequest -> {
            assertThat(tokenRequest.body())
                    .contains("grant_type=refresh_token")
                    .contains("refresh_token=first-refresh-token");
            assertThat(tokenRequest.authorization()).isEqualTo(basicAuth("bff-client", "bff-client-demo-secret"));
        });
        assertThat(FAKE.requestsTo("/api/orders")).singleElement()
                .extracting(RecordedRequest::authorization).isEqualTo("Bearer fresh-access-token");

        // The old refresh token is useless after rotation, so the new one must replace it.
        OAuth2AuthorizedClient stored = storedClient(session);
        assertThat(stored.getAccessToken().getTokenValue()).isEqualTo("fresh-access-token");
        assertThat(stored.getRefreshToken().getTokenValue()).isEqualTo("rotated-refresh-token");
    }

    @Test
    void tokenRejectedByTheApiIsForgottenAndTheUserIsAskedToSignInAgain() throws Exception {
        FAKE.respond("/api/orders", request -> new Response(401, "",
                Map.of("WWW-Authenticate", "Bearer error=\"invalid_token\"")));
        MockHttpSession session = sessionHoldingTokens(validAccessToken("revoked-access-token"), "alice-refresh-token");

        mvc.perform(get("/api/orders").session(session).with(authentication(aliceAuthentication())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.title").value("Reauthentication required"));

        assertThat(storedClient(session)).isNull();
    }

    @Test
    void withoutAStoredTokenTheUserIsAskedToSignInAgain() throws Exception {
        mvc.perform(get("/api/orders").session(new MockHttpSession()).with(authentication(aliceAuthentication())))
                .andExpect(status().isUnauthorized());

        assertThat(FAKE.requestsTo("/api/orders")).isEmpty();
    }

    @Test
    void apiFailureIsReportedAsBadGatewayWithoutLeakingTheDownstreamResponse() throws Exception {
        FAKE.respond("/api/orders", request -> new Response(500, "{\"trace\":\"internal details\"}", Map.of()));
        MockHttpSession session = sessionHoldingTokens(validAccessToken("alice-access-token"), "alice-refresh-token");

        mvc.perform(get("/api/orders").session(session).with(authentication(aliceAuthentication())))
                .andExpect(status().isBadGateway())
                .andExpect(content().string(not(containsString("internal details"))));
    }

    private MockHttpSession sessionHoldingTokens(OAuth2AccessToken accessToken, String refreshToken) {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(registration(), "alice", accessToken,
                new OAuth2RefreshToken(refreshToken, Instant.now()));
        authorizedClients.saveAuthorizedClient(client, alice(), request, new MockHttpServletResponse());
        return session;
    }

    private OAuth2AuthorizedClient storedClient(MockHttpSession session) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return authorizedClients.loadAuthorizedClient(REGISTRATION_ID, alice(), request);
    }

    private static OAuth2AccessToken validAccessToken(String value) {
        Instant now = Instant.now();
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, value, now, now.plus(Duration.ofMinutes(10)),
                Set.of("openid", "profile", "orders.read"));
    }

    private static Authentication alice() {
        return new TestingAuthenticationToken("alice", null);
    }

    private static String basicAuth(String clientId, String secret) {
        return "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private ClientRegistration registration() {
        return clientRegistrations.findByRegistrationId(REGISTRATION_ID);
    }
}
