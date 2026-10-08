package com.backend.auth.jwt.keys;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

/**
 * DEMO key store: RSA key pairs generated in memory at startup. A restart therefore invalidates every
 * issued access token, and two instances would not share keys. In production the private key lives in
 * a KMS or HSM (or at least a secret manager) and only its public half is published.
 *
 * <p>Rotation without downtime is three steps, spaced out in time:
 * <ol>
 *   <li>{@link #publishNewKey()}: the new public key appears in the JWKS, but nothing is signed with
 *       it yet. Wait at least one JWKS cache lifetime so every verifier has it.</li>
 *   <li>{@link #activate(String)}: new tokens carry the new {@code kid}. Tokens signed with the old
 *       key still verify, because the old public key is still published.</li>
 *   <li>{@link #retire(String)}: once the longest-lived token signed with the old key has expired
 *       (access-token TTL plus clock skew), remove it.</li>
 * </ol>
 */
@Component
public class InMemorySigningKeyStore implements SigningKeyStore {

    private static final Logger log = LoggerFactory.getLogger(InMemorySigningKeyStore.class);

    // 2048 bits is the minimum for RS256; prefer 3072 for keys expected to be in use after 2030.
    private static final int RSA_KEY_SIZE = 2048;

    private record State(List<RSAKey> keys, String activeKeyId) {
    }

    private volatile State state;

    public InMemorySigningKeyStore() {
        RSAKey first = generate();
        this.state = new State(List.of(first), first.getKeyID());
        log.info("Generated in-memory RS256 signing key kid={} (DEMO ONLY: tokens do not survive a restart)",
                first.getKeyID());
    }

    @Override
    public String activeKeyId() {
        return state.activeKeyId();
    }

    @Override
    public List<JWK> allSigningKeys() {
        return List.copyOf(state.keys());
    }

    /** Step 1 of a rotation: publish a new key for verification only. Returns its {@code kid}. */
    public synchronized String publishNewKey() {
        RSAKey next = generate();
        List<RSAKey> keys = new ArrayList<>(state.keys());
        keys.add(next);
        state = new State(List.copyOf(keys), state.activeKeyId());
        log.info("Published signing key kid={} (not yet used for signing)", next.getKeyID());
        return next.getKeyID();
    }

    /** Step 2: sign new tokens with an already published key. */
    public synchronized void activate(String keyId) {
        requirePublished(keyId);
        state = new State(state.keys(), keyId);
        log.info("Signing key kid={} is now active", keyId);
    }

    /** Step 3: stop trusting a key. Every token it signed fails verification from now on. */
    public synchronized void retire(String keyId) {
        requirePublished(keyId);
        if (keyId.equals(state.activeKeyId())) {
            throw new IllegalStateException("Activate another key before retiring the active one");
        }
        List<RSAKey> keys = state.keys().stream().filter(key -> !key.getKeyID().equals(keyId)).toList();
        state = new State(keys, state.activeKeyId());
        log.info("Retired signing key kid={}", keyId);
    }

    private void requirePublished(String keyId) {
        boolean published = state.keys().stream().anyMatch(key -> key.getKeyID().equals(keyId));
        if (!published) {
            throw new IllegalArgumentException("Unknown kid: " + keyId);
        }
    }

    private static RSAKey generate() {
        try {
            return new RSAKeyGenerator(RSA_KEY_SIZE)
                    .keyUse(KeyUse.SIGNATURE)
                    // Binding the key to one algorithm is what makes algorithm confusion impossible:
                    // this key is RS256 and nothing else.
                    .algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint(true)          // kid = RFC 7638 thumbprint: opaque, unique, stable
                    .issueTime(new Date())
                    .generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not generate an RSA signing key", e);
        }
    }
}
