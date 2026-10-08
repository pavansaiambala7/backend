package com.backend.auth.jwt;

import static com.backend.auth.jwt.AuthFlows.bearer;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import com.backend.auth.jwt.keys.SigningKeyStore;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Every check the resource server must make, one forged or broken token at a time. Each bad token
 * differs from a valid one in exactly one way, so a 401 proves that specific check exists.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AccessTokenValidationTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    SigningKeyStore keys;

    @Test
    void validTokenSignedWithTheServerKeyIsAccepted() throws Exception {
        callApiWith(TestTokens.signWithServerKey(keys, claims().build())).andExpect(status().isOk());
    }

    @Test
    void requestWithoutTokenIsRejected() throws Exception {
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, startsWith("Bearer")));
    }

    @Test
    void tamperedSignatureIsRejected() throws Exception {
        String token = TestTokens.signWithServerKey(keys, claims().build());
        int lastSignatureChar = token.length() - 2;   // not the very last char: its low bits may be padding
        char flipped = token.charAt(lastSignatureChar) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, lastSignatureChar) + flipped + token.substring(lastSignatureChar + 1);

        expectInvalidToken(callApiWith(tampered));
    }

    @Test
    void tamperedPayloadIsRejected() throws Exception {
        String[] parts = TestTokens.signWithServerKey(keys, claims().build()).split("\\.");
        String elevated = TestTokens.parseUnverified(
                TestTokens.signWithServerKey(keys, claims().claim("scope", "orders:read orders:write admin").build()))
                .getParsedParts()[1].toString();
        // Payload of one token with the signature of another: the signature no longer matches.
        expectInvalidToken(callApiWith(parts[0] + "." + elevated + "." + parts[2]));
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        // Correctly signed by our issuer, but meant for another API.
        String token = TestTokens.signWithServerKey(keys, claims().audience("https://billing.example.com").build());
        expectInvalidToken(callApiWith(token));
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = TestTokens.signWithServerKey(keys, claims().issuer("https://evil.example.com").build());
        expectInvalidToken(callApiWith(token));
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        Instant now = Instant.now();
        String token = TestTokens.signWithServerKey(keys, claims()
                .issueTime(Date.from(now.minus(Duration.ofMinutes(20))))
                .notBeforeTime(Date.from(now.minus(Duration.ofMinutes(20))))
                .expirationTime(Date.from(now.minus(Duration.ofMinutes(5))))
                .build());
        expectInvalidToken(callApiWith(token));
    }

    @Test
    void clockSkewToleranceIsTheConfiguredThirtySecondsNotTheLibraryDefaultSixty() throws Exception {
        Instant now = Instant.now();
        String expired10sAgo = expiringAt(now.minusSeconds(10));
        String expired45sAgo = expiringAt(now.minusSeconds(45));

        callApiWith(expired10sAgo).andExpect(status().isOk());   // within 30 s skew
        expectInvalidToken(callApiWith(expired45sAgo));          // Spring's default 60 s would accept this
    }

    @Test
    void tokenNotYetValidIsRejected() throws Exception {
        Instant inFiveMinutes = Instant.now().plus(Duration.ofMinutes(5));
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys,
                claims().notBeforeTime(Date.from(inFiveMinutes)).build())));
    }

    @Test
    void tokenIssuedInTheFutureIsRejected() throws Exception {
        // A future iat means a broken issuer clock or a forged token; nbf alone would not catch it here.
        Instant now = Instant.now();
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, claims()
                .issueTime(Date.from(now.plus(Duration.ofMinutes(5))))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(20))))
                .build())));
    }

    @Test
    void unsignedAlgNoneTokenIsRejected() throws Exception {
        expectInvalidToken(callApiWith(TestTokens.unsigned(claims().build())));
    }

    @Test
    void hs256TokenSignedWithOurPublicKeyIsRejected() throws Exception {
        // The algorithm-confusion attack: only works if the verifier lets the header choose the algorithm.
        expectInvalidToken(callApiWith(TestTokens.hs256SignedWithPublicKey(keys, claims().build())));
    }

    @Test
    void tokenSignedByAnotherKeyClaimingOurKidIsRejected() throws Exception {
        RSAKey attackerKey = TestTokens.newAttackerKey(keys.activeKeyId());
        String token = TestTokens.sign(attackerKey, TestTokens.serverHeader(keys).build(), claims().build());
        expectInvalidToken(callApiWith(token));
    }

    @Test
    void keyEmbeddedInTheTokenHeaderIsNeverTrusted() throws Exception {
        // "Verify me with this key": the jwk header points at the attacker's own public key.
        RSAKey attackerKey = TestTokens.newAttackerKey("attacker");
        JWSHeader header = TestTokens.serverHeader(keys).keyID("attacker").jwk(attackerKey.toPublicJWK()).build();
        expectInvalidToken(callApiWith(TestTokens.sign(attackerKey, header, claims().build())));
    }

    @Test
    void unknownKidIsRejected() throws Exception {
        JWSHeader header = TestTokens.serverHeader(keys).keyID("no-such-key").build();
        expectInvalidToken(callApiWith(TestTokens.sign(TestTokens.activeKey(keys), header, claims().build())));
    }

    @Test
    void jwtOfAnotherTypeIsNotAcceptedAsAnAccessToken() throws Exception {
        // Same key, same claims, but typ JWT (for example an ID token): cross-JWT confusion.
        JWSHeader idTokenLike = TestTokens.serverHeader(keys).type(JOSEObjectType.JWT).build();
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, idTokenLike, claims().build())));

        JWSHeader untyped = TestTokens.serverHeader(keys).type(null).build();
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, untyped, claims().build())));
    }

    @Test
    void tokenMissingRequiredClaimsIsRejected() throws Exception {
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, claims().expirationTime(null).build())));
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, claims().subject(null).build())));
        expectInvalidToken(callApiWith(TestTokens.signWithServerKey(keys, claims().claim("client_id", null).build())));
    }

    private String expiringAt(Instant expiresAt) {
        return TestTokens.signWithServerKey(keys, claims()
                .issueTime(Date.from(expiresAt.minus(Duration.ofMinutes(15))))
                .notBeforeTime(Date.from(expiresAt.minus(Duration.ofMinutes(15))))
                .expirationTime(Date.from(expiresAt))
                .build());
    }

    private static JWTClaimsSet.Builder claims() {
        return TestTokens.validClaims("alice", "orders:read orders:write");
    }

    private ResultActions callApiWith(String token) throws Exception {
        return mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, bearer(token)));
    }

    private static void expectInvalidToken(ResultActions result) throws Exception {
        result.andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("error=\"invalid_token\"")));
    }
}
