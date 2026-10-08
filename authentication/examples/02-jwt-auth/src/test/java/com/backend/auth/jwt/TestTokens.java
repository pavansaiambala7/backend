package com.backend.auth.jwt;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import com.backend.auth.jwt.keys.SigningKeyStore;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Builds tokens in tests, both legitimate ones signed with the server's real key (to vary one claim at a
 * time) and the classic forgeries. Uses Nimbus directly so the header can be anything an attacker wants.
 */
public final class TestTokens {

    public static final String ISSUER = "http://localhost:8082";
    public static final String AUDIENCE = "jwt-demo-api";
    public static final String CLIENT_ID = "jwt-demo-web";

    private TestTokens() {
    }

    /** Claims exactly like the ones the server issues, valid for five minutes from now. */
    public static JWTClaimsSet.Builder validClaims(String subject, String scope) {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject(subject)
                .claim("scope", scope)
                .claim("client_id", CLIENT_ID)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .jwtID(UUID.randomUUID().toString());
    }

    /** The header the server uses: RS256, the active kid, typ at+jwt. */
    public static JWSHeader.Builder serverHeader(SigningKeyStore keys) {
        return new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keys.activeKeyId())
                .type(new JOSEObjectType("at+jwt"));
    }

    /** Signs with the server's real active private key. */
    public static String signWithServerKey(SigningKeyStore keys, JWSHeader header, JWTClaimsSet claims) {
        return sign(activeKey(keys), header, claims);
    }

    public static String signWithServerKey(SigningKeyStore keys, JWTClaimsSet claims) {
        return signWithServerKey(keys, serverHeader(keys).build(), claims);
    }

    public static String sign(RSAKey key, JWSHeader header, JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code alg: none}: header and payload, empty signature. */
    public static String unsigned(JWTClaimsSet claims) {
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"at+jwt\"}");
        String payload = base64Url(claims.toString());
        return header + "." + payload + ".";
    }

    /**
     * Algorithm confusion: an HS256 token whose HMAC key is the server's PUBLIC key (PEM text, which an
     * attacker can download from the JWKS). A verifier that lets the header pick the algorithm and
     * feeds it "the key" would accept this.
     */
    public static String hs256SignedWithPublicKey(SigningKeyStore keys, JWTClaimsSet claims) {
        RSAKey publicKey = activeKey(keys).toPublicJWK();
        try {
            byte[] pem = toPem(publicKey).getBytes(StandardCharsets.US_ASCII);
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .keyID(publicKey.getKeyID())
                    .type(new JOSEObjectType("at+jwt"))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new MACSigner(pem));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static RSAKey newAttackerKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static RSAKey activeKey(SigningKeyStore keys) {
        return keys.allSigningKeys().stream()
                .filter(key -> key.getKeyID().equals(keys.activeKeyId()))
                .map(RSAKey.class::cast)
                .findFirst()
                .orElseThrow();
    }

    /** Header, claims and signature of a compact JWT, for assertions. Does NOT verify anything. */
    public static SignedJWT parseUnverified(String token) {
        try {
            return SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static String toPem(RSAKey publicKey) throws JOSEException {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(publicKey.toPublicKey().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
