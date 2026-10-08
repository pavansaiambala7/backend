package com.backend.auth.jwt.keys;

import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

/**
 * The issuer's signing keys. Each key has a {@code kid}; exactly one is active for signing, and every
 * published key (active, about to become active, or recently retired from signing) stays available
 * for verification so tokens survive a rotation.
 */
public interface SigningKeyStore {

    /** The {@code kid} new tokens are signed with. */
    String activeKeyId();

    /** Every published key including private parts. Only the token encoder may see these. */
    List<JWK> allSigningKeys();

    /** Public halves of every published key: what the JWKS endpoint serves and verifiers trust. */
    default JWKSet publicJwkSet() {
        return new JWKSet(allSigningKeys()).toPublicJWKSet();
    }
}
