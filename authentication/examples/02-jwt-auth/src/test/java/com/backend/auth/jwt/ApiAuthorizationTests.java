package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.bearer;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/** Valid tokens, different permissions: 403 (authenticated, not allowed) rather than 401. */
@SpringBootTest
@AutoConfigureMockMvc
class ApiAuthorizationTests {

    @Autowired
    MockMvc mvc;

    @Test
    void insufficientScopeIsForbidden() throws Exception {
        String bobToken = AuthFlows.login(mvc, "bob", AuthFlows.BOB_PASSWORD).accessToken();   // orders:read only

        mvc.perform(get("/api/orders").header(HttpHeaders.AUTHORIZATION, bearer(bobToken)))
                .andExpect(status().isOk());

        mvc.perform(post("/api/orders")
                        .header(HttpHeaders.AUTHORIZATION, bearer(bobToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"keyboard\",\"quantity\":1}"))
                .andExpect(status().isForbidden())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"insufficient_scope\"")));
    }

    @Test
    void writeScopeAllowsCreatingAndOrdersStayWithTheirOwner() throws Exception {
        String aliceToken = AuthFlows.loginAlice(mvc).accessToken();
        String bobToken = AuthFlows.login(mvc, "bob", AuthFlows.BOB_PASSWORD).accessToken();

        mvc.perform(post("/api/orders")
                        .header(HttpHeaders.AUTHORIZATION, bearer(aliceToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"item\":\"alice-only-notebook\",\"quantity\":2}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.owner").value("alice"));

        mvc.perform(get("/api/orders").header(HttpHeaders.AUTHORIZATION, bearer(aliceToken)))
                .andExpect(jsonPath("$[*].item", hasItem("alice-only-notebook")));
        // Scope says "may read orders"; the subject decides whose. Bob never sees Alice's orders.
        mvc.perform(get("/api/orders").header(HttpHeaders.AUTHORIZATION, bearer(bobToken)))
                .andExpect(jsonPath("$[*].item", not(hasItem("alice-only-notebook"))));
    }

    @Test
    void scopeClaimBecomesScopeAuthorities() throws Exception {
        String bobToken = AuthFlows.login(mvc, "bob", AuthFlows.BOB_PASSWORD).accessToken();
        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(bobToken)))
                .andExpect(jsonPath("$.authorities", hasItem("SCOPE_orders:read")))
                .andExpect(jsonPath("$.authorities", not(hasItem("SCOPE_orders:write"))));
    }

    @Test
    void endpointsNotExplicitlyAllowedAreDenied() throws Exception {
        String aliceToken = AuthFlows.loginAlice(mvc).accessToken();
        mvc.perform(get("/api/admin").header(HttpHeaders.AUTHORIZATION, bearer(aliceToken)))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/admin"))
                .andExpect(status().isUnauthorized());
    }
}
