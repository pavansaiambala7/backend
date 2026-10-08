package com.backend.auth.mfa.crypto;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

/**
 * AES-256 keys that encrypt TOTP secrets at rest.
 *
 * <p>Several keys may be listed so keys can rotate: new secrets are encrypted with {@code activeKeyId}, and
 * every stored ciphertext names the key that decrypts it. In production these values come from a KMS or a
 * secret manager (AWS KMS / Secrets Manager, Google Cloud KMS, Azure Key Vault, HashiCorp Vault), injected at
 * startup, never from a file in the repository.
 *
 * @param activeKeyId key used for new encryptions
 * @param keys        key id to Base64-encoded 256-bit key
 */
@Validated
@ConfigurationProperties("mfa.encryption")
public record EncryptionProperties(@NotBlank String activeKeyId, @NotEmpty Map<String, String> keys) {
}
