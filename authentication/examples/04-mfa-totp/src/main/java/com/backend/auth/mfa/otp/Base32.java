package com.backend.auth.mfa.otp;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Locale;

/**
 * Base32 from RFC 4648, section 6: the alphabet {@code A-Z 2-7}. Authenticator apps expect TOTP secrets
 * in this encoding (the otpauth:// "Key Uri Format"), without {@code =} padding.
 *
 * <p>The alphabet has no {@code 0}, {@code 1}, {@code 8} or {@code 9}, so it also suits codes that people
 * type by hand, such as recovery codes.
 */
public final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] DECODE = new int[128];

    static {
        Arrays.fill(DECODE, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            DECODE[ALPHABET[i]] = i;
        }
    }

    private Base32() {
    }

    /** Encodes with RFC 4648 padding, e.g. {@code "f" -> "MY======"}. */
    public static String encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length + 4) / 5 * 8);
        int buffer = 0;
        int bitsInBuffer = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xff);
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5) {
                out.append(ALPHABET[(buffer >>> (bitsInBuffer - 5)) & 0x1f]);
                bitsInBuffer -= 5;
            }
        }
        if (bitsInBuffer > 0) {
            out.append(ALPHABET[(buffer << (5 - bitsInBuffer)) & 0x1f]);
        }
        while (out.length() % 8 != 0) {
            out.append('=');
        }
        return out.toString();
    }

    /** Encodes without padding, the form used in otpauth:// URIs. */
    public static String encodeUnpadded(byte[] data) {
        String padded = encode(data);
        int end = padded.indexOf('=');
        return end < 0 ? padded : padded.substring(0, end);
    }

    /**
     * Decodes Base32, ignoring case, padding, spaces and dashes (people copy secrets in groups like
     * {@code JBSW Y3DP}).
     *
     * @throws IllegalArgumentException if the input contains any other character
     */
    public static byte[] decode(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(text.length() * 5 / 8);
        int buffer = 0;
        int bitsInBuffer = 0;
        for (char c : text.toUpperCase(Locale.ROOT).toCharArray()) {
            if (c == '=' || c == ' ' || c == '-') {
                continue;
            }
            int value = c < DECODE.length ? DECODE[c] : -1;
            if (value < 0) {
                throw new IllegalArgumentException("Not a Base32 character: '" + c + "'");
            }
            buffer = (buffer << 5) | value;
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8) {
                out.write((buffer >>> (bitsInBuffer - 8)) & 0xff);
                bitsInBuffer -= 8;
            }
        }
        return out.toByteArray();
    }
}
