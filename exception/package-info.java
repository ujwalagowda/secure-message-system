/**
 * exception package
 *
 * Contains custom exception classes and a global exception handler.
 *
 *   - GlobalExceptionHandler.java         @RestControllerAdvice that catches all
 *                                         exceptions and returns structured JSON
 *                                         error responses with appropriate HTTP codes.
 *
 *   - UserNotFoundException.java          Thrown when a user ID or username does
 *                                         not exist in the database. → 404 Not Found
 *
 *   - MessageAccessDeniedException.java   Thrown when a user tries to read or
 *                                         decrypt a message they do not own. → 403 Forbidden
 *
 *   - EncryptionException.java            Thrown when RSA encryption fails
 *                                         (e.g. invalid public key). → 500 Internal Server Error
 *
 *   - DecryptionException.java            Thrown when RSA decryption fails
 *                                         (e.g. invalid private key or corrupted
 *                                         ciphertext). → 500 Internal Server Error
 *
 * These classes will be implemented in Phase 3.
 */
package com.securemsg.exception;
