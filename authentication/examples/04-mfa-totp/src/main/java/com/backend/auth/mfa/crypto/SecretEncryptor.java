package com.backend.auth.mfa.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * Encrypts small secrets with AES-256-GCM.
 *
 * <p>A TOTP secret cannot be hashed like a password: the server needs the raw key to compute the HMAC. So it is
 * encrypted, with the key kept outside the database: a database dump or a stolen backup alone reveals nothing.
 *
 * <p>Stored format: {@code <keyId>:<Base64(nonce || ciphertext || tag)>}.
 */
@Component
public class SecretEncryptor {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int NONCE_BYTES = 12;     // 96 bits, the size GCM is designed for
    private static final int TAG_BITS = 128;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9_-]{1,64}");

    private final SecureRandom random = new SecureRandom();
    private final Map<String, SecretKey> keys = new HashMap<>();
    private final String activeKeyId;

    public SecretEncryptor(EncryptionProperties properties) {
        properties.keys().forEach((id, base64) -> {
            if (!KEY_ID.matcher(id).matches()) {
                throw new IllegalStateException("Invalid encryption key id '" + id + "'");
            }
            byte[] key = Base64.getDecoder().decode(base64);
            if (key.length != 32) {
                throw new IllegalStateException("Encryption key '" + id + "' must be 256 bits, got " + key.length * 8);
            }
            keys.put(id, new SecretKeySpec(key, "AES"));
        });
        if (!keys.containsKey(properties.activeKeyId())) {
            throw new IllegalStateException("No encryption key configured for active id '" + properties.activeKeyId() + "'");
        }
        this.activeKeyId = properties.activeKeyId();
    }

    /**
     * @param associatedData authenticated but not encrypted context, here the owner's username. Decryption fails
     *                       unless the same value is supplied, so someone who can write to the database cannot
     *                       copy their own encrypted secret into another user's row.
     */
    public String encrypt(byte[] plaintext, String associatedData) {
        byte[] nonce = new byte[NONCE_BYTES];
        // A fresh random nonce per encryption: reusing a nonce with the same GCM key breaks confidentiality
        // and lets an attacker forge ciphertexts.
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(activeKeyId), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] stored = ByteBuffer.allocate(nonce.length + ciphertext.length).put(nonce).put(ciphertext).array();
            return activeKeyId + ":" + Base64.getEncoder().encodeToString(stored);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    /**
     * @throws IllegalStateException if the key is unknown, the ciphertext was modified, or the associated data
     *                               differs from the value used to encrypt
     */
    public byte[] decrypt(String stored, String associatedData) {
        int separator = stored.indexOf(':');
        SecretKey key = separator > 0 ? keys.get(stored.substring(0, separator)) : null;
        if (key == null) {
            throw new IllegalStateException("Unknown encryption key for stored secret");
        }
        byte[] data = Base64.getDecoder().decode(stored.substring(separator + 1));
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, data, 0, NONCE_BYTES));
            cipher.updateAAD(associatedData.getBytes(StandardCharsets.UTF_8));
            return cipher.doFinal(data, NONCE_BYTES, data.length - NONCE_BYTES);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Stored secret failed authentication (tampered, or wrong owner)", e);
        }
    }
}
