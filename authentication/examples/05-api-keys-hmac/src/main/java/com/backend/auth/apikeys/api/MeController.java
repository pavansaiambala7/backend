package com.backend.auth.apikeys.api;

import java.util.List;
import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.backend.auth.apikeys.security.ApiKeyPrincipal;

/** Lets an integration check which key it is using and what that key may do. */
@RestController
class MeController {

    record Me(String owner, UUID keyId, String keyPrefix, List<String> authorities) {
    }

    @GetMapping("/v1/me")
    Me me(Authentication authentication) {
        ApiKeyPrincipal principal = (ApiKeyPrincipal) authentication.getPrincipal();
        List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList();
        return new Me(principal.owner(), principal.keyId(), principal.keyPrefix(), authorities);
    }
}
