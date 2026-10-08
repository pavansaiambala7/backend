package com.backend.auth.resourceserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Authorization rules, with Spring Security's {@code jwt()} post-processor standing in for an already
 * validated token. Token validation itself is covered by {@link AccessTokenValidationTests}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OrdersApiAuthorizationTests {

    @Autowired
    MockMvc mvc;

    @Test
    void requestWithoutATokenGetsABearerChallenge() throws Exception {
        mvc.perform(get("/api/orders"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")))
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE,
                        containsString("resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"")));
    }

    @Test
    void protectedResourceMetadataNamesTheAuthorizationServerAndScopes() throws Exception {
        mvc.perform(get("/.well-known/oauth-protected-resource"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resource").value("http://localhost"))
                .andExpect(jsonPath("$.authorization_servers", contains("http://localhost:9000")))
                .andExpect(jsonPath("$.scopes_supported", contains("orders.read")))
                .andExpect(jsonPath("$.bearer_methods_supported", contains("header")));
    }

    @Test
    void tokenWithOrdersReadScopeReturnsOnlyTheSubjectsOrders() throws Exception {
        mvc.perform(get("/api/orders").with(tokenFor("alice", "SCOPE_orders.read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"))
                .andExpect(jsonPath("$.clientId").value("bff-client"))
                .andExpect(jsonPath("$.orders[*].id", containsInAnyOrder("A-1001", "A-1002")));

        mvc.perform(get("/api/orders").with(tokenFor("bob", "SCOPE_orders.read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orders[*].id", containsInAnyOrder("B-2001")));
    }

    @Test
    void tokenWithoutTheRequiredScopeIsForbidden() throws Exception {
        // Authenticated (valid token) but not authorized: 403 with insufficient_scope, not 401.
        mvc.perform(get("/api/orders").with(tokenFor("alice", "SCOPE_openid", "SCOPE_profile")))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("insufficient_scope")));
    }

    @Test
    void endpointsWithoutAnExplicitRuleAreDenied() throws Exception {
        mvc.perform(get("/api/admin").with(tokenFor("alice", "SCOPE_orders.read")))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/orders").with(tokenFor("alice", "SCOPE_orders.read")))
                .andExpect(status().isForbidden());
    }

    @Test
    void apiIsStatelessAndNeverSetsASessionCookie() throws Exception {
        MvcResult result = mvc.perform(get("/api/orders").with(tokenFor("alice", "SCOPE_orders.read")))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andReturn();
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    private static RequestPostProcessor tokenFor(String subject, String... authorities) {
        return jwt()
                .jwt(token -> token.subject(subject).claim("client_id", "bff-client"))
                .authorities(Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toArray(GrantedAuthority[]::new));
    }
}
