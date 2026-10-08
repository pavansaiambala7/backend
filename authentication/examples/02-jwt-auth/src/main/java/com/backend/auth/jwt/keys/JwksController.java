package com.backend.auth.jwt.keys;

import java.time.Duration;
import java.util.Map;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the public signing keys (RFC 7517 JWK Set) so any service can verify our tokens without
 * sharing a secret. Verifiers look up the key by the token's {@code kid}.
 */
@RestController
class JwksController {

    /**
     * How long verifiers may cache the key set. A rotation must wait at least this long between
     * publishing a new key and signing with it.
     */
    static final Duration CACHE_LIFETIME = Duration.ofMinutes(5);

    private final SigningKeyStore keys;

    JwksController(SigningKeyStore keys) {
        this.keys = keys;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Map<String, Object>> jwks() {
        // publicJwkSet() strips d, p, q, dp, dq and qi: private key material must never leave the issuer.
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(CACHE_LIFETIME).cachePublic())
                .body(keys.publicJwkSet().toJSONObject());
    }
}
