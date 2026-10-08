package com.backend.auth.clientapp;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.OidcLoginRequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;

final class BffTestSupport {

    static final String REGISTRATION_ID = "auth-server";
    static final String ISSUER = "http://localhost:9000";
    static final String ALICE_ID_TOKEN = "alice-id-token-value";

    private BffTestSupport() {
    }

    /** A mocked OIDC login for Alice through the app's real client registration. */
    static OidcLoginRequestPostProcessor aliceLogin(ClientRegistration registration) {
        return oidcLogin()
                .clientRegistration(registration)
                .idToken(token -> token
                        .tokenValue(ALICE_ID_TOKEN)
                        .issuer(ISSUER)
                        .subject("alice")
                        .audience(List.of("bff-client"))
                        .claim("name", "Alice Anderson")
                        .claim("preferred_username", "alice")
                        .authTime(Instant.parse("2026-10-08T09:00:00Z")));
    }

    /**
     * The same signed-in Alice as an {@code Authentication}, for tests that must not use
     * {@code oidcLogin()}: that post-processor also installs a test authorized client (access token
     * "access-token") into the application's OAuth2AuthorizedClientManager for the request, which would
     * hide the tokens the test stored in the session.
     */
    static OAuth2AuthenticationToken aliceAuthentication() {
        Instant issuedAt = Instant.now();
        OidcIdToken idToken = OidcIdToken.withTokenValue(ALICE_ID_TOKEN)
                .issuer(ISSUER)
                .subject("alice")
                .audience(List.of("bff-client"))
                .claim("name", "Alice Anderson")
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(600))
                .build();
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("OIDC_USER"));
        return new OAuth2AuthenticationToken(new DefaultOidcUser(authorities, idToken), authorities, REGISTRATION_ID);
    }

    /** Query parameters of a redirect URL, percent-decoded. */
    static Map<String, String> queryParams(String url) {
        Map<String, String> params = new LinkedHashMap<>();
        UriComponentsBuilder.fromUriString(url).build().getQueryParams().forEach((name, values) ->
                params.put(name, values.isEmpty() || values.get(0) == null ? null
                        : URLDecoder.decode(values.get(0), StandardCharsets.UTF_8)));
        return params;
    }
}
