package com.backend.auth.jwt.api;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Shows what the resource server learned from a validated access token. */
@RestController
class MeController {

    @GetMapping("/api/me")
    Map<String, Object> me(JwtAuthenticationToken authentication) {
        List<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        Instant expiresAt = authentication.getToken().getExpiresAt();
        return Map.of(
                "subject", authentication.getName(),
                "authorities", authorities,
                "token_id", authentication.getToken().getId(),
                "expires_at", expiresAt.toString());
    }
}
