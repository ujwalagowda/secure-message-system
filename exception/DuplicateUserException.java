package com.securemsg.exception;

/**
 * DuplicateUserException
 *
 * Thrown during registration when the submitted username or email
 * already exists in the database.
 *
 * Examples:
 *   - POST /api/auth/register — username already taken
 *   - POST /api/auth/register — email already registered
 *
 * Handled by GlobalExceptionHandler → HTTP 409 Conflict
 */
public class DuplicateUserException extends RuntimeException {

    public DuplicateUserException(String message) {
        super(message);
    }
}
