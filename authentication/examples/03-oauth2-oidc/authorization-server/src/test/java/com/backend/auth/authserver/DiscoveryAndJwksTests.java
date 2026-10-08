package com.backend.auth.authserver;

import static com.backend.auth.authserver.OAuthTestSupport.ISSUER;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class DiscoveryAndJwksTests {

    @Autowired
    MockMvc mvc;

    @Test
    void openIdDiscoveryDocumentPublishesIssuerEndpointsAndOnlySecureOptions() throws Exception {
        mvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                // Clients must compare this with the issuer they were configured with (mix-up defense).
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.authorization_endpoint").value(ISSUER + "/oauth2/authorize"))
                .andExpect(jsonPath("$.token_endpoint").value(ISSUER + "/oauth2/token"))
                .andExpect(jsonPath("$.jwks_uri").value(ISSUER + "/oauth2/jwks"))
                .andExpect(jsonPath("$.userinfo_endpoint").value(ISSUER + "/userinfo"))
                .andExpect(jsonPath("$.end_session_endpoint").value(ISSUER + "/connect/logout"))
                .andExpect(jsonPath("$.revocation_endpoint").value(ISSUER + "/oauth2/revoke"))
                // Only the code flow: no implicit (response_type=token / id_token).
                .andExpect(jsonPath("$.response_types_supported", contains("code")))
                .andExpect(jsonPath("$.grant_types_supported",
                        hasItems("authorization_code", "refresh_token", "client_credentials")))
                .andExpect(jsonPath("$.grant_types_supported", not(hasItem("password"))))
                .andExpect(jsonPath("$.grant_types_supported", not(hasItem("implicit"))))
                // S256 only: "plain" PKCE would put the verifier itself in the front channel.
                .andExpect(jsonPath("$.code_challenge_methods_supported", contains("S256")))
                .andExpect(jsonPath("$.id_token_signing_alg_values_supported", contains("RS256")))
                .andExpect(jsonPath("$.scopes_supported", hasItem("openid")))
                // Dynamic client registration is off: nobody can register a client over the network.
                .andExpect(jsonPath("$.registration_endpoint").doesNotExist());
    }

    @Test
    void oauthAuthorizationServerMetadataUsesTheSameIssuer() throws Exception {
        mvc.perform(get("/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ISSUER))
                .andExpect(jsonPath("$.code_challenge_methods_supported", contains("S256")));
    }

    @Test
    void jwksPublishesOnlyThePublicSigningKey() throws Exception {
        mvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty())
                // The private exponent and CRT parameters must never leave the server.
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dp").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dq").doesNotExist())
                .andExpect(jsonPath("$.keys[0].qi").doesNotExist());
    }
}
