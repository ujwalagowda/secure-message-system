package com.securemsg.exception;

/**
 * EncryptionException
 *
 * Thrown when the RSA encryption operation fails in RSAService.
 *
 * Possible causes:
 *   - Recipient's public key is invalid or corrupted in the database
 *   - Plaintext message exceeds the RSA-2048 size limit (max ~245 bytes)
 *   - Java Cipher initialisation failure
 *
 * Handled by GlobalExceptionHandler → HTTP 500 Internal Server Error
 * (The root cause is logged server-side but not exposed to the client.)
 */
public class EncryptionException extends RuntimeException {

    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
