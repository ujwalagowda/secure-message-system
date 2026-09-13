package com.securemsg.exception;

/**
 * DecryptionException
 *
 * Thrown when the RSA decryption operation fails in RSAService.
 *
 * Possible causes:
 *   - Receiver's private key is invalid or corrupted in the database
 *   - Ciphertext has been tampered with or is corrupted
 *   - Java Cipher initialisation failure
 *
 * Handled by GlobalExceptionHandler → HTTP 500 Internal Server Error
 * (The root cause is logged server-side but not exposed to the client.)
 */
public class DecryptionException extends RuntimeException {

    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
