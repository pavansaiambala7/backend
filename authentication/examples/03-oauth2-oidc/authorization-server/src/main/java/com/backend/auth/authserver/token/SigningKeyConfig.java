package com.backend.auth.authserver.token;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * The key that signs access tokens and ID tokens; its public half is published at /oauth2/jwks.
 *
 * <p><strong>DEMO ONLY:</strong> the RSA key pair is generated at startup and lives only in memory.
 * Every restart therefore invalidates all issued tokens, and two instances would sign with different
 * keys. In production, load the private key from a KMS/HSM or a secret store (or let the KMS sign),
 * keep it stable across instances, and rotate it on a schedule: publish the next key in the JWKS
 * before signing with it, and keep the previous key published until its last token has expired.
 */
@Configuration(proxyBeanMethods = false)
class SigningKeyConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                // The kid in each token header tells verifiers which JWKS entry to use, which is what
                // makes key rotation possible without downtime.
                .keyID(UUID.randomUUID().toString())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /** Validates access tokens presented to this server's own /userinfo endpoint. */
    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("RSA is not available in this JVM", ex);
        }
    }
}
