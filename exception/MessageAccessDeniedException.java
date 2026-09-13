package com.securemsg.exception;

/**
 * MessageAccessDeniedException
 *
 * Thrown when a user attempts to read or decrypt a message
 * that does not belong to them.
 *
 * Example:
 *   - GET /api/messages/{id}/decrypt — authenticated user is
 *     not the intended receiver of this message
 *
 * Handled by GlobalExceptionHandler → HTTP 403 Forbidden
 */
public class MessageAccessDeniedException extends RuntimeException {

    public MessageAccessDeniedException(String message) {
        super(message);
    }
}
