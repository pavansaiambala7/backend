package com.backend.auth.jwt.token;

import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.backend.auth.jwt.keys.SigningKeyStore;

/** Issues RS256 access tokens following the RFC 9068 JWT access-token profile. */
@Service
public class AccessTokenService {

    /** RFC 9068 explicit typing: stops an ID token or other JWT from being accepted as an access token. */
    public static final String ACCESS_TOKEN_TYPE = "at+jwt";

    private final JwtEncoder encoder;
    private final SigningKeyStore keys;
    private final JwtProperties properties;
    private final Clock clock;

    AccessTokenService(JwtEncoder encoder, SigningKeyStore keys, JwtProperties properties, Clock clock) {
        this.encoder = encoder;
        this.keys = keys;
        this.properties = properties;
        this.clock = clock;
    }

    public AccessToken issue(String subject, Collection<String> scopes) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(properties.accessTokenTtl());
        List<String> sortedScopes = scopes.stream().distinct().sorted().toList();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(keys.activeKeyId())        // selects the signing key; tells verifiers which public key to use
                .type(ACCESS_TOKEN_TYPE)
                .build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.issuer())
                .subject(subject)
                .audience(List.of(properties.audience()))
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())   // jti: lets you log, trace or deny-list a single token
                .claim("client_id", properties.clientId())
                .claim("scope", String.join(" ", sortedScopes))
                .build();

        String value = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new AccessToken(value, now, expiresAt, sortedScopes);
    }
}
