package com.securemsg.controller;

import com.securemsg.dto.AuthResponse;
import com.securemsg.dto.LoginRequest;
import com.securemsg.dto.RegisterRequest;
import com.securemsg.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController
 *
 * Handles user registration and login HTTP requests.
 * Both endpoints are publicly accessible — no JWT required.
 *
 * Endpoints:
 *   POST /api/auth/register   — create a new user account
 *   POST /api/auth/login      — authenticate and receive a JWT token
 *
 * Responsibilities of this controller:
 *   - Accept and validate the incoming JSON request body (@Valid)
 *   - Delegate all business logic to AuthService
 *   - Return the appropriate HTTP status code and response body
 *
 * This controller does NOT:
 *   - Perform any business logic directly
 *   - Access the database directly
 *   - Perform any cryptographic operations
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/auth/register
    // ─────────────────────────────────────────────────────────

    /**
     * Registers a new user account.
     *
     * Request body (JSON):
     * {
     *   "username" : "alice",
     *   "email"    : "alice@example.com",
     *   "password" : "secret123"
     * }
     *
     * Success response — HTTP 201 Created:
     * {
     *   "token"     : "eyJhbGciOiJIUzI1NiJ9...",
     *   "tokenType" : "Bearer",
     *   "userId"    : 1,
     *   "username"  : "alice",
     *   "email"     : "alice@example.com",
     *   "role"      : "USER",
     *   "message"   : "Registration successful. Welcome, alice!"
     * }
     *
     * Error responses:
     *   400 Bad Request  — validation failure (blank fields, invalid email, short password)
     *   409 Conflict     — username or email already exists
     *
     * @param request validated RegisterRequest DTO
     * @return HTTP 201 with AuthResponse body on success
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/auth/login
    // ─────────────────────────────────────────────────────────

    /**
     * Authenticates a user and returns a JWT token.
     *
     * The usernameOrEmail field accepts either a username or an email address.
     *
     * Request body (JSON):
     * {
     *   "usernameOrEmail" : "alice",
     *   "password"        : "secret123"
     * }
     *
     * OR:
     * {
     *   "usernameOrEmail" : "alice@example.com",
     *   "password"        : "secret123"
     * }
     *
     * Success response — HTTP 200 OK:
     * {
     *   "token"     : "eyJhbGciOiJIUzI1NiJ9...",
     *   "tokenType" : "Bearer",
     *   "userId"    : 1,
     *   "username"  : "alice",
     *   "email"     : "alice@example.com",
     *   "role"      : "USER",
     *   "message"   : "Login successful. Welcome back, alice!"
     * }
     *
     * Error responses:
     *   400 Bad Request   — validation failure (blank fields)
     *   401 Unauthorized  — wrong credentials or disabled account
     *
     * How to use the token:
     *   Include it in all subsequent protected requests:
     *   Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
     *
     * @param request validated LoginRequest DTO
     * @return HTTP 200 with AuthResponse body on success
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }
}
