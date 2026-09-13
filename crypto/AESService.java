package com.securemsg.crypto;

import com.securemsg.exception.DecryptionException;
import com.securemsg.exception.EncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AESService — AES-256-GCM authenticated encryption for image data.
 *
 * ─── Why AES-GCM for images? ───────────────────────────────────────────────
 *
 *  RSA-2048 can only encrypt ~190 bytes directly (OAEP/SHA-256 overhead).
 *  Images are megabytes large. Hybrid encryption solves this:
 *
 *    1. Generate a random AES-256 key (32 bytes, 256 bits)
 *    2. AES-256-GCM encrypts the image bytes (no size limit)
 *    3. RSA-2048-OAEP encrypts the 32-byte AES key (fits easily in RSA)
 *    4. Only the tiny encrypted AES key + IV are stored alongside the image
 *
 *  GCM (Galois/Counter Mode):
 *    - Provides BOTH confidentiality (counter mode encryption)
 *      AND integrity/authenticity (GHASH authentication tag)
 *    - 128-bit auth tag: any bit-flip in the ciphertext is detected on decrypt
 *    - Nonce/IV: 96 bits (12 bytes) — must be unique per encryption
 *    - No padding needed (stream cipher mode)
 *
 * ─── Operations ────────────────────────────────────────────────────────────
 *
 *  1. generateAESKey()               — random 256-bit AES SecretKey
 *  2. generateIV()                   — random 96-bit GCM IV
 *  3. encodeKey(SecretKey)           — SecretKey → Base64 string
 *  4. decodeKey(String)              — Base64 string → SecretKey
 *  5. encodeIV(byte[])               — IV bytes → Base64 string
 *  6. decodeIV(String)               — Base64 string → IV bytes
 *  7. encrypt(data, key, iv)         — AES-256-GCM encrypt → byte[]
 *  8. decrypt(cipherData, key, iv)   — AES-256-GCM decrypt → byte[]
 *
 * ─── Security rules ────────────────────────────────────────────────────────
 *
 *  - AES key is NEVER stored in plaintext. It is RSA-encrypted before storage.
 *  - AES key is NEVER logged.
 *  - AES key is NEVER returned to the frontend.
 *  - IV is safe to store alongside ciphertext (not a secret, just unique).
 *  - Decryption failure throws DecryptionException (GCM tag mismatch or wrong key).
 */
@Service
public class AESService {

    private static final Logger logger = LoggerFactory.getLogger(AESService.class);

    private static final String AES_ALGORITHM          = "AES";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int    AES_KEY_BITS           = 256;   // 32 bytes
    private static final int    GCM_IV_BYTES           = 12;    // 96 bits — recommended for GCM
    private static final int    GCM_TAG_BITS           = 128;   // 16 bytes — maximum auth tag length

    // ─────────────────────────────────────────────────────────────────────────
    // 1. KEY GENERATION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generates a cryptographically random AES-256 secret key.
     *
     * Uses Java's KeyGenerator seeded with SecureRandom.
     * This key is used to AES-GCM-encrypt the image bytes.
     * It must be RSA-encrypted immediately after generation
     * and never stored in plaintext.
     *
     * @return fresh AES-256 SecretKey
     */
    public SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES_ALGORITHM);
            keyGen.init(AES_KEY_BITS, new SecureRandom());
            SecretKey key = keyGen.generateKey();
            logger.debug("AES-256 key generated");
            // Do NOT log key bytes
            return key;
        } catch (Exception e) {
            logger.error("AES key generation failed: {}", e.getMessage(), e);
            throw new EncryptionException("Failed to generate AES key", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. IV GENERATION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generates a cryptographically random 96-bit (12-byte) GCM IV (nonce).
     *
     * The IV MUST be unique for every encryption operation with the same key.
     * Since we generate a fresh random key per image, this is already guaranteed,
     * but using SecureRandom for the IV as well is best practice.
     *
     * The IV is not secret and can be stored alongside the ciphertext.
     *
     * @return 12-byte IV array
     */
    public byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3 & 4. KEY ENCODING / DECODING
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encodes a SecretKey to a Base64 string for temporary handling
     * before RSA encryption. The result of this method must immediately
     * be passed to RSAService.encrypt() — it must NEVER be stored in plaintext.
     *
     * @param key AES SecretKey
     * @return Base64-encoded key bytes
     */
    public String encodeKey(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs a SecretKey from its raw Base64-encoded bytes.
     * Called only during decryption after RSA has already decrypted
     * the AES key bytes.
     *
     * @param base64Key Base64-encoded AES key bytes (from RSA decryption output)
     * @return reconstructed AES-256 SecretKey
     */
    public SecretKey decodeKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5 & 6. IV ENCODING / DECODING
    // ─────────────────────────────────────────────────────────────────────────

    /** Encodes IV bytes to a Base64 string for database storage. */
    public String encodeIV(byte[] iv) {
        return Base64.getEncoder().encodeToString(iv);
    }

    /** Decodes a Base64 IV string back to bytes for use in Cipher init. */
    public byte[] decodeIV(String base64IV) {
        return Base64.getDecoder().decode(base64IV);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. ENCRYPTION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encrypts image bytes using AES-256-GCM.
     *
     * Output format:
     *   [GCM ciphertext bytes][128-bit authentication tag]
     *   (Java's GCM implementation appends the tag automatically)
     *
     * The authentication tag ensures that any modification to the
     * ciphertext is detected during decryption (AEADBadTagException).
     *
     * @param plainData  raw image bytes
     * @param key        AES-256 SecretKey (from generateAESKey())
     * @param iv         96-bit IV (from generateIV())
     * @return           ciphertext bytes including 128-bit GCM auth tag
     * @throws EncryptionException on any cipher failure
     */
    public byte[] encrypt(byte[] plainData, SecretKey key, byte[] iv) {
        if (plainData == null || plainData.length == 0) {
            throw new EncryptionException("Image data cannot be empty");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
            byte[] cipherBytes = cipher.doFinal(plainData);
            logger.debug("AES-256-GCM encryption complete: {} bytes → {} bytes",
                    plainData.length, cipherBytes.length);
            // Do NOT log plainData or cipherBytes
            return cipherBytes;
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            logger.error("AES-GCM encryption failed: {}", e.getMessage(), e);
            throw new EncryptionException("AES-GCM image encryption failed", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. DECRYPTION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts AES-256-GCM ciphertext back to original image bytes.
     *
     * GCM authentication is verified automatically during doFinal().
     * If the ciphertext has been tampered with, or if the wrong key/IV
     * is supplied, an AEADBadTagException is thrown (wrapped as
     * DecryptionException) — the corrupt data is never returned.
     *
     * @param cipherData  ciphertext bytes (including 128-bit GCM auth tag)
     * @param key         AES-256 SecretKey (after RSA decryption of stored key)
     * @param iv          96-bit IV (from database gcm_iv column)
     * @return            original image bytes
     * @throws DecryptionException if auth tag fails or cipher error occurs
     */
    public byte[] decrypt(byte[] cipherData, SecretKey key, byte[] iv) {
        if (cipherData == null || cipherData.length == 0) {
            throw new DecryptionException("Encrypted image data is empty");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
            GCMParameterSpec paramSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
            byte[] plainData = cipher.doFinal(cipherData);
            logger.debug("AES-256-GCM decryption complete: {} bytes → {} bytes",
                    cipherData.length, plainData.length);
            // Do NOT log plainData
            return plainData;
        } catch (DecryptionException e) {
            throw e;
        } catch (Exception e) {
            // AEADBadTagException (tampered data) also caught here
            logger.error("AES-GCM decryption failed: {}", e.getMessage(), e);
            throw new DecryptionException("AES-GCM image decryption failed — data may be corrupted or tampered", e);
        }
    }
}
