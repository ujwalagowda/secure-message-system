package com.securemsg.crypto;

import com.securemsg.exception.DecryptionException;
import com.securemsg.exception.EncryptionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSAService
 *
 * The ONLY class responsible for all RSA cryptographic operations in this project.
 * No other class performs encryption or decryption.
 *
 * ─── RSA Algorithm Facts (for viva) ──────────────────────────────────────────
 *
 *  RSA (Rivest–Shamir–Adleman) is an asymmetric cryptographic algorithm.
 *  It uses a key PAIR:
 *    - Public key  → used to ENCRYPT data    (can be shared openly)
 *    - Private key → used to DECRYPT data    (must be kept secret)
 *
 *  Key size used: RSA-2048
 *    - Modulus n = 2048 bits = 256 bytes
 *    - Security based on the mathematical difficulty of factoring large integers
 *
 *  Padding scheme: OAEP (Optimal Asymmetric Encryption Padding)
 *    Full name: RSA/ECB/OAEPWithSHA-256AndMGF1Padding
 *    - OAEP is the modern, recommended padding for RSA encryption
 *    - It adds randomness to each encryption so the same plaintext
 *      produces different ciphertext each time (semantic security)
 *    - SHA-256 is used INTERNALLY by the OAEP padding scheme as a
 *      hash function parameter. It is NOT a separate encryption step.
 *      This project remains RSA-only — OAEP is part of the RSA standard.
 *
 *  Message size limit with OAEP + SHA-256:
 *    Max plaintext = keySize/8 − 2×hashLength − 2
 *                  = 256 − 2×32 − 2 = 190 bytes
 *    We enforce 190 characters (1 char ≈ 1 byte for ASCII/Latin)
 *    This limit is validated before every encryption call.
 *
 * ─── Operations provided ──────────────────────────────────────────────────────
 *
 *  1. generateKeyPair()          — produces a new RSA-2048 KeyPair
 *  2. encodePublicKey()          — KeyPair → Base64 string for DB storage
 *  3. encodePrivateKey()         — KeyPair → Base64 string for DB storage
 *  4. decodePublicKey()          — Base64 string → PublicKey object
 *  5. decodePrivateKey()         — Base64 string → PrivateKey object
 *  6. encrypt(plaintext, pubKey) — RSA-OAEP encrypt → Base64 ciphertext
 *  7. decrypt(ciphertext, privK) — Base64 ciphertext → original plaintext
 *
 * ─── Security rules enforced here ────────────────────────────────────────────
 *
 *  - Plaintext is NEVER logged
 *  - Private keys are NEVER logged
 *  - Encryption errors: root cause logged server-side, generic message to client
 *  - Decryption errors: root cause logged server-side, generic message to client
 */
@Service
public class RSAService {

    private static final Logger logger = LoggerFactory.getLogger(RSAService.class);

    /** RSA algorithm identifier used with KeyPairGenerator and KeyFactory. */
    private static final String RSA_ALGORITHM = "RSA";

    /**
     * Full cipher transformation string.
     * RSA/ECB/OAEPWithSHA-256AndMGF1Padding
     *
     * - RSA       : asymmetric algorithm
     * - ECB       : mode identifier (not a block cipher mode here — required by JCE API)
     * - OAEP...   : padding scheme (SHA-256 used as the hash function parameter within OAEP)
     *
     * NOTE: "ECB" in the JCE transformation string for RSA does NOT mean
     * AES-ECB. It is a required placeholder in the Java Cipher API.
     * No AES or block cipher is used anywhere in this project.
     */
    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * RSA-2048 key size in bits.
     * Injected from application.properties: rsa.key-size=2048
     */
    @Value("${rsa.key-size:2048}")
    private int keySize;

    /**
     * Maximum plaintext length enforced before encryption.
     * For RSA-2048 + OAEP/SHA-256: max = 256 − 2×32 − 2 = 190 bytes.
     * Injected from application.properties: rsa.max-message-length=190
     */
    @Value("${rsa.max-message-length:190}")
    private int maxMessageLength;

    // ─────────────────────────────────────────────────────────────────────────
    // 1. KEY PAIR GENERATION
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Generates a new RSA-2048 key pair.
     *
     * Called once per user at registration time.
     * The public key is stored in the database and can be shared.
     * The private key is stored in the database and NEVER returned via API.
     *
     * Java API used:
     *   KeyPairGenerator.getInstance("RSA")
     *   keyPairGenerator.initialize(2048)
     *   keyPairGenerator.generateKeyPair()
     *
     * @return a KeyPair containing a PublicKey and a PrivateKey
     * @throws EncryptionException if key generation fails (should never happen on standard JRE)
     */
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(keySize);                 // RSA-2048
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            logger.debug("RSA-{} key pair generated successfully", keySize);
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            // This cannot happen on any standard Java 21 JRE — RSA is always available
            logger.error("RSA key pair generation failed: {}", e.getMessage(), e);
            throw new EncryptionException("RSA key pair generation failed", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. KEY ENCODING — KeyPair → Base64 String for database storage
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encodes a PublicKey to a Base64 string for storage in the database.
     *
     * Uses X.509 encoding: key.getEncoded() returns the standard
     * SubjectPublicKeyInfo format (X509EncodedKeySpec).
     *
     * @param publicKey the RSA public key
     * @return Base64-encoded string representation
     */
    public String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Encodes a PrivateKey to a Base64 string for storage in the database.
     *
     * Uses PKCS#8 encoding: key.getEncoded() returns the standard
     * PrivateKeyInfo format (PKCS8EncodedKeySpec).
     *
     * @param privateKey the RSA private key
     * @return Base64-encoded string representation
     */
    public String encodePrivateKey(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. KEY DECODING — Base64 String → Key objects for cryptographic use
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Reconstructs a PublicKey from its Base64-encoded database string.
     *
     * Java API used:
     *   X509EncodedKeySpec  — wraps the decoded bytes
     *   KeyFactory.getInstance("RSA").generatePublic(spec)
     *
     * @param base64PublicKey Base64 string from the database
     * @return the reconstructed RSA PublicKey
     * @throws EncryptionException if the key bytes are invalid or corrupted
     */
    public PublicKey decodePublicKey(String base64PublicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.error("Failed to decode RSA public key: {}", e.getMessage());
            throw new EncryptionException("Invalid RSA public key", e);
        }
    }

    /**
     * Reconstructs a PrivateKey from its Base64-encoded database string.
     *
     * Java API used:
     *   PKCS8EncodedKeySpec — wraps the decoded bytes
     *   KeyFactory.getInstance("RSA").generatePrivate(spec)
     *
     * SECURITY: This method is called server-side only during decryption.
     * The private key NEVER travels beyond this service layer.
     *
     * @param base64PrivateKey Base64 string from the database
     * @return the reconstructed RSA PrivateKey
     * @throws DecryptionException if the key bytes are invalid or corrupted
     */
    public PrivateKey decodePrivateKey(String base64PrivateKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            logger.error("Failed to decode RSA private key");
            // Do NOT log the key value or the exception message (may contain key data)
            throw new DecryptionException("Invalid RSA private key", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. ENCRYPTION — plaintext → Base64 RSA ciphertext
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Encrypts a plaintext message using the recipient's RSA public key.
     *
     * Encryption flow:
     *   plaintext (String)
     *     → UTF-8 bytes
     *     → Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
     *     → cipher.init(ENCRYPT_MODE, recipientPublicKey)
     *     → cipher.doFinal(bytes)
     *     → Base64.encode(cipherBytes)
     *     → stored in messages.encrypted_content (database)
     *
     * The plaintext is NEVER stored. Only the Base64 ciphertext is stored.
     *
     * @param plaintext        the message to encrypt (max 190 characters)
     * @param base64PublicKey  recipient's Base64-encoded public key from DB
     * @return Base64-encoded RSA ciphertext
     * @throws EncryptionException if the message is too long or encryption fails
     */
    public String encrypt(String plaintext, String base64PublicKey) {
        // Enforce RSA-2048 + OAEP message size limit
        if (plaintext == null || plaintext.isBlank()) {
            throw new EncryptionException("Message cannot be empty");
        }
        if (plaintext.length() > maxMessageLength) {
            throw new EncryptionException(
                "Message exceeds RSA-2048 limit. Maximum allowed: "
                + maxMessageLength + " characters. "
                + "Provided: " + plaintext.length() + " characters."
            );
        }

        try {
            PublicKey publicKey = decodePublicKey(base64PublicKey);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedBytes = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8)
            );

            String ciphertext = Base64.getEncoder().encodeToString(encryptedBytes);
            logger.debug("Message encrypted successfully using RSA-{} OAEP", keySize);
            // Do NOT log plaintext or ciphertext content
            return ciphertext;

        } catch (EncryptionException e) {
            throw e; // already wrapped — rethrow as-is
        } catch (Exception e) {
            logger.error("RSA encryption failed: {}", e.getMessage(), e);
            throw new EncryptionException("RSA encryption failed", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. DECRYPTION — Base64 RSA ciphertext → plaintext
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Decrypts a Base64-encoded RSA ciphertext using the recipient's private key.
     *
     * Decryption flow:
     *   Base64 ciphertext (from database)
     *     → Base64.decode(ciphertext) → byte[]
     *     → Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
     *     → cipher.init(DECRYPT_MODE, recipientPrivateKey)
     *     → cipher.doFinal(cipherBytes)
     *     → new String(plaintextBytes, UTF-8)
     *     → returned ONLY to the authenticated recipient
     *
     * SECURITY:
     *   - The private key is loaded from DB, used here, and discarded.
     *   - The private key never leaves this service.
     *   - The decrypted plaintext is returned to the service layer,
     *     which returns it only to the message's authenticated receiver.
     *
     * @param base64Ciphertext  Base64-encoded encrypted message from the database
     * @param base64PrivateKey  recipient's Base64-encoded private key from DB
     * @return the original plaintext message
     * @throws DecryptionException if the ciphertext is corrupted or key is invalid
     */
    public String decrypt(String base64Ciphertext, String base64PrivateKey) {
        try {
            PrivateKey privateKey = decodePrivateKey(base64PrivateKey);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedBytes = cipher.doFinal(
                Base64.getDecoder().decode(base64Ciphertext)
            );

            String plaintext = new String(decryptedBytes, StandardCharsets.UTF_8);
            logger.debug("Message decrypted successfully using RSA-{} OAEP", keySize);
            // Do NOT log the decrypted plaintext
            return plaintext;

        } catch (DecryptionException e) {
            throw e; // already wrapped — rethrow as-is
        } catch (Exception e) {
            logger.error("RSA decryption failed: {}", e.getMessage(), e);
            throw new DecryptionException("RSA decryption failed", e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. UTILITY — expose configured limits for validation elsewhere
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Returns the configured maximum message length.
     * Used by MessageService to validate before attempting encryption.
     *
     * @return maximum number of characters allowed per message
     */
    public int getMaxMessageLength() {
        return maxMessageLength;
    }
}
