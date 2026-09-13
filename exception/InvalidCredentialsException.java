package com.securemsg.exception;

/**
 * InvalidCredentialsException
 *
 * Thrown during login when the provided username/email or password
 * does not match any record in the database, or when the account
 * is disabled.
 *
 * The message intentionally does not reveal whether the username
 * or the password was wrong (to prevent user enumeration attacks).
 *
 * Handled by GlobalExceptionHandler → HTTP 401 Unauthorized
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
