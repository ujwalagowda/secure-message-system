package com.securemsg.exception;

/**
 * UserNotFoundException
 *
 * Thrown when a requested user does not exist in the database.
 *
 * Examples:
 *   - GET /api/users/{id}    — ID does not exist
 *   - POST /api/messages     — receiver ID does not exist
 *
 * Handled by GlobalExceptionHandler → HTTP 404 Not Found
 */
public class UserNotFoundException extends RuntimeException {

    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(Long id) {
        super("User not found with id: " + id);
    }
}
