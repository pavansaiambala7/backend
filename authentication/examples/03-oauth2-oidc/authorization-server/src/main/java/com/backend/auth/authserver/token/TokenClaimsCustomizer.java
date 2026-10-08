package com.backend.auth.authserver.token;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import com.backend.auth.authserver.AuthServerProperties.ApiResource;
import com.backend.auth.authserver.user.UserProfiles;

/**
 * Adds the claims that the defaults leave out.
 *
 * <ul>
 *   <li>Access tokens: {@code aud} names the API the token is for (by default it would be the client ID),
 *       and {@code client_id} records which client obtained it (RFC 9068).</li>
 *   <li>ID tokens: profile claims when the {@code profile} scope was granted (also served by /userinfo).</li>
 * </ul>
 */
final class TokenClaimsCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final List<ApiResource> apis;
    private final UserProfiles userProfiles;

    TokenClaimsCustomizer(List<ApiResource> apis, UserProfiles userProfiles) {
        this.apis = List.copyOf(apis);
        this.userProfiles = userProfiles;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            customizeAccessToken(context);
        }
        else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
            customizeIdToken(context);
        }
    }

    private void customizeAccessToken(JwtEncodingContext context) {
        // The audience is what lets an API refuse a token minted for somebody else: a token for the
        // orders API is useless at the billing API, and an ID token (aud = client ID) is useless at both.
        List<String> audiences = audiencesFor(context.getAuthorizedScopes());
        if (!audiences.isEmpty()) {
            context.getClaims().audience(audiences);
        }
        context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
    }

    private void customizeIdToken(JwtEncodingContext context) {
        if (!context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
            return;
        }
        userProfiles.find(context.getPrincipal().getName()).ifPresent(profile -> context.getClaims()
                .claim(StandardClaimNames.NAME, profile.fullName())
                .claim(StandardClaimNames.PREFERRED_USERNAME, profile.username()));
    }

    private List<String> audiencesFor(Set<String> grantedScopes) {
        return apis.stream()
                .filter(api -> !Collections.disjoint(api.scopes(), grantedScopes))
                .map(ApiResource::audience)
                .toList();
    }
}
