package ru.kraser.three_token_security.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public final class CsrfTokenSigner {

    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private final SecretKeySpec secretKey;

    public CsrfTokenSigner(String csrfHmacSecret) {
        byte[] keyBytes = Base64.getDecoder().decode(csrfHmacSecret);
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException(
                    "CSRF HMAC secret must be at least 32 bytes (256 bits). " +
                            "Generate with: openssl rand -base64 32");
        }
        this.secretKey = new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }

    /*public CsrfTokenSigner(String secret) {
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
    }*/

    public String sign(String stringToken, String userId) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(secretKey);
            String userIdAndToken = (userId == null ? "" : userId) + "|" + stringToken    ;
            byte[] hmacBytes = mac.doFinal(userIdAndToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot sign csrf_token", e);
        }
    }

    public boolean isValidSignature(String stringToken, String signature, String userId) {
        String expected = sign(stringToken, userId);
        // Сравнение, устойчивое к timing-атакам
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                signature.getBytes(StandardCharsets.UTF_8)
        );
    }
}
