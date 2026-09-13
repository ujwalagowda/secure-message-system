package com.securemsg.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * GlobalExceptionHandler
 *
 * Centralised exception handler for all REST controllers.
 * Uses @RestControllerAdvice so it applies globally across every
 * controller without needing try/catch in individual endpoints.
 *
 * Every handler returns a consistent JSON error response:
 * {
 *   "status"    : 404,
 *   "error"     : "Not Found",
 *   "message"   : "User not found with id: 99",
 *   "timestamp" : "2026-09-11T14:00:00"
 * }
 *
 * Internal details (stack traces, SQL errors) are logged server-side
 * but NEVER included in the response body sent to the client.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ─────────────────────────────────────────────────────────
    // Helper — builds a consistent error response map
    // ─────────────────────────────────────────────────────────

    private Map<String, Object> buildError(HttpStatus status, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status",    status.value());
        body.put("error",     status.getReasonPhrase());
        body.put("message",   message);
        body.put("timestamp", LocalDateTime.now().toString());
        return body;
    }

    // ─────────────────────────────────────────────────────────
    // 400 — Validation errors (@Valid on request DTOs)
    // ─────────────────────────────────────────────────────────

    /**
     * Handles @Valid validation failures on request bodies.
     * Collects all field-level validation errors and returns them
     * in a single response so the client sees all problems at once.
     *
     * Response shape:
     * {
     *   "status"  : 400,
     *   "error"   : "Bad Request",
     *   "message" : "Validation failed",
     *   "errors"  : { "username": "Username is required", ... },
     *   "timestamp": "..."
     * }
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationErrors(
            MethodArgumentNotValidException ex) {

        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fe.getField(), fe.getDefaultMessage());
        }

        Map<String, Object> body = buildError(HttpStatus.BAD_REQUEST, "Validation failed");
        body.put("errors", fieldErrors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    // ─────────────────────────────────────────────────────────
    // 401 — Invalid credentials
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(
            InvalidCredentialsException ex) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(buildError(HttpStatus.UNAUTHORIZED, ex.getMessage()));
    }

    // ─────────────────────────────────────────────────────────
    // 403 — Message access denied
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(MessageAccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleMessageAccessDenied(
            MessageAccessDeniedException ex) {
        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(buildError(HttpStatus.FORBIDDEN, ex.getMessage()));
    }

    // ─────────────────────────────────────────────────────────
    // 404 — User not found
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(
            UserNotFoundException ex) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(buildError(HttpStatus.NOT_FOUND, ex.getMessage()));
    }

    // ─────────────────────────────────────────────────────────
    // 409 — Duplicate username or email
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(DuplicateUserException.class)
    public ResponseEntity<Map<String, Object>> handleDuplicateUser(
            DuplicateUserException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(buildError(HttpStatus.CONFLICT, ex.getMessage()));
    }

    // ─────────────────────────────────────────────────────────
    // 500 — RSA encryption failure
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(EncryptionException.class)
    public ResponseEntity<Map<String, Object>> handleEncryptionFailure(
            EncryptionException ex) {
        // Log full details server-side only — never expose crypto internals to client
        logger.error("RSA encryption failed: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildError(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Message encryption failed. Please try again."));
    }

    // ─────────────────────────────────────────────────────────
    // 500 — RSA decryption failure
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(DecryptionException.class)
    public ResponseEntity<Map<String, Object>> handleDecryptionFailure(
            DecryptionException ex) {
        // Log full details server-side only — never expose crypto internals to client
        logger.error("RSA decryption failed: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildError(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Message decryption failed. Please try again."));
    }

    // ─────────────────────────────────────────────────────────
    // 500 — Catch-all for any unhandled exception
    // ─────────────────────────────────────────────────────────

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        // Always log the full exception internally
        logger.error("Unhandled exception: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildError(HttpStatus.INTERNAL_SERVER_ERROR,
                        "An unexpected error occurred. Please try again later."));
    }
}
