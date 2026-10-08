package com.backend.auth.resourceserver;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.resourceserver.security.AccessTokenValidators;
import com.backend.auth.resourceserver.security.ResourceServerProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 * Real, signed JWTs against the production validation rules. Only the key source differs from
 * production: instead of fetching the authorization server's JWKS over HTTP, the decoder trusts one
 * test key. The algorithm allowlist and every claim validator are the production ones.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(AccessTokenValidationTests.TestKeyDecoderConfig.class)
class AccessTokenValidationTests {

    private static final String ISSUER = "http://localhost:9000";
    private static final RSAKey TRUSTED_KEY = generateRsaKey("trusted-test-key");
    private static final RSAKey UNKNOWN_KEY = generateRsaKey("attacker-key");

    @Autowired
    MockMvc mvc;

    @TestConfiguration(proxyBeanMethods = false)
    static class TestKeyDecoderConfig {

        @Bean
        @Primary
        JwtDecoder testKeyJwtDecoder(ResourceServerProperties properties) throws JOSEException {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(TRUSTED_KEY.toRSAPublicKey())
                    .signatureAlgorithm(SignatureAlgorithm.RS256)
                    .build();
            decoder.setJwtValidator(AccessTokenValidators.forApi(properties));
            return decoder;
        }
    }

    @Test
    void validTokenFromTheTrustedIssuerIsAccepted() throws Exception {
        callOrdersApi(signedWith(TRUSTED_KEY, claims -> { }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("alice"));
    }

    @Test
    void validTokenWithoutTheRequiredScopeIsForbidden() throws Exception {
        callOrdersApi(signedWith(TRUSTED_KEY, claims -> claims.claim("scope", List.of("openid", "profile"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        Instant twoMinutesAgo = Instant.now().minus(Duration.ofMinutes(2));   // beyond the 60 s clock skew
        assertInvalidToken(signedWith(TRUSTED_KEY, claims -> claims
                .issueTime(Date.from(twoMinutesAgo.minus(Duration.ofMinutes(10))))
                .notBeforeTime(Date.from(twoMinutesAgo.minus(Duration.ofMinutes(10))))
                .expirationTime(Date.from(twoMinutesAgo))));
    }

    @Test
    void tokenThatIsNotYetValidIsRejected() throws Exception {
        assertInvalidToken(signedWith(TRUSTED_KEY, claims -> claims
                .notBeforeTime(Date.from(Instant.now().plus(Duration.ofMinutes(5))))));
    }

    @Test
    void tokenFromAnotherIssuerIsRejected() throws Exception {
        assertInvalidToken(signedWith(TRUSTED_KEY, claims -> claims.issuer("https://evil.example")));
    }

    @Test
    void tokenForAnotherApiIsRejected() throws Exception {
        assertInvalidToken(signedWith(TRUSTED_KEY, claims -> claims.audience("billing-api")));
    }

    @Test
    void idTokenIsNotAcceptedAsAnAccessToken() throws Exception {
        // Same issuer, same key, but addressed to the client (aud = client ID): proof of login for the
        // client, never a credential for an API.
        assertInvalidToken(signedWith(TRUSTED_KEY, claims -> claims
                .audience("bff-client")
                .claim("azp", "bff-client")
                .claim("nonce", "n-0S6_WzA2Mj")));
    }

    @Test
    void tokenSignedWithAnUnknownKeyIsRejected() throws Exception {
        assertInvalidToken(signedWith(UNKNOWN_KEY, claims -> { }));
    }

    @Test
    void algorithmConfusionWithHs256AndThePublicKeyAsSecretIsRejected() throws Exception {
        // The classic attack: sign with HMAC using the (public!) RSA key bytes and hope the server uses
        // the key it has for whatever "alg" the header names. The RS256 allowlist stops it.
        SignedJWT forged = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims(claims -> { }));
        forged.sign(new MACSigner(TRUSTED_KEY.toRSAPublicKey().getEncoded()));
        assertInvalidToken(forged.serialize());
    }

    @Test
    void unsignedTokenWithAlgNoneIsRejected() throws Exception {
        assertInvalidToken(new PlainJWT(claims(claims -> { })).serialize());
    }

    @Test
    void malformedTokenIsRejected() throws Exception {
        assertInvalidToken("not-a-jwt");
    }

    private ResultActions callOrdersApi(String token) throws Exception {
        return mvc.perform(get("/api/orders").header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
    }

    private void assertInvalidToken(String token) throws Exception {
        callOrdersApi(token)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));
    }

    private static String signedWith(RSAKey key, Consumer<JWTClaimsSet.Builder> customizer) throws JOSEException {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                claims(customizer));
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    /** Claims shaped like the authorization server's access tokens; each test changes one thing. */
    private static JWTClaimsSet claims(Consumer<JWTClaimsSet.Builder> customizer) {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .audience("orders-api")
                .claim("scope", List.of("openid", "profile", "orders.read"))
                .claim("client_id", "bff-client")
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(10))))
                .jwtID(UUID.randomUUID().toString());
        customizer.accept(claims);
        return claims.build();
    }

    private static RSAKey generateRsaKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        }
        catch (JOSEException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
