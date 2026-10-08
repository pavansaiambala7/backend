package com.backend.auth.jwt.token;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.backend.auth.jwt.keys.SigningKeyStore;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/** The token encoder (issuer side) and decoder (resource-server side). */
@Configuration(proxyBeanMethods = false)
class JwtConfig {

    @Bean
    JwtEncoder jwtEncoder(SigningKeyStore keys) {
        // Read the key store on every call so a rotation takes effect without a restart.
        // The encoder picks the key whose kid matches the JWS header.
        JWKSource<SecurityContext> signingKeys =
                (selector, context) -> selector.select(new JWKSet(keys.allSigningKeys()));
        return new NimbusJwtEncoder(signingKeys);
    }

    /**
     * Verifies access tokens. This service checks tokens it issued itself, so it reads the public keys
     * in-process. Another service would use {@code NimbusJwtDecoder.withJwkSetUri(".../.well-known/jwks.json")}
     * with exactly the same algorithm allowlist and validators.
     */
    @Bean
    JwtDecoder jwtDecoder(SigningKeyStore keys, JwtProperties properties, Clock clock) {
        JWKSource<SecurityContext> publicKeys = (selector, context) -> selector.select(keys.publicJwkSet());
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(publicKeys)
                // The algorithm allowlist. The verifier, not the token header, decides the algorithm:
                // alg=none, HS256 signed with our public key (algorithm confusion) and anything else
                // are rejected before a single claim is read.
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(accessTokenValidator(properties, clock));
        return decoder;
    }

    /**
     * RFC 9068 checks: {@code typ} is {@code at+jwt}; {@code iss} and {@code aud} match exactly;
     * {@code exp}, {@code iat}, {@code sub}, {@code jti} and {@code client_id} are present;
     * {@code exp} and {@code nbf} hold, and {@code iat} is not in the future, with a small clock skew.
     */
    static OAuth2TokenValidator<Jwt> accessTokenValidator(JwtProperties properties, Clock clock) {
        Duration skew = properties.clockSkew();
        JwtTimestampValidator expiryAndNotBefore = new JwtTimestampValidator(skew);
        expiryAndNotBefore.setClock(clock);
        // Not JwtIssuedAtValidator: that is a freshness check for DPoP proofs (iat within the skew of now
        // in both directions) and would reject a perfectly valid access token older than the skew.
        OAuth2TokenValidator<Jwt> notIssuedInTheFuture = new JwtClaimValidator<Instant>(JwtClaimNames.IAT,
                issuedAt -> issuedAt != null && !issuedAt.isAfter(clock.instant().plus(skew)));

        return JwtValidators.createAtJwtValidator()
                .issuer(properties.issuer())
                .audience(properties.audience())
                // The builder's "exp" and "iat" entries both carry a JwtTimestampValidator with the
                // default 60 s skew. Replace both, or that default still accepts tokens that expired
                // up to 60 s ago, whatever skew is configured here.
                .validators(validators -> {
                    validators.put(JwtClaimNames.EXP,
                            new DelegatingOAuth2TokenValidator<>(required(JwtClaimNames.EXP), expiryAndNotBefore));
                    validators.put(JwtClaimNames.IAT, notIssuedInTheFuture);
                })
                .build();
    }

    private static OAuth2TokenValidator<Jwt> required(String claim) {
        return new JwtClaimValidator<Instant>(claim, Objects::nonNull);
    }
}
